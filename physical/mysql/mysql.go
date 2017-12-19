package mysql

import (
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"fmt"
	"io/ioutil"
	"net/url"
	pkgPath "path"
	"sort"
	"strconv"
	"strings"
	"time"

	log "github.com/mgutz/logxi/v1"

	"github.com/armon/go-metrics"
	mysql "github.com/go-sql-driver/mysql"
	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/helper/strutil"
	"github.com/hashicorp/vault/physical"
	"os"
	"sync"
)

// Unreserved tls key
// Reserved values are "true", "false", "skip-verify"
const (
	mysqlTLSKey = "default"

	// The lock TTL matches the default that Consul API uses, 15 seconds.
	MySQLLockTTL = 15 * time.Second

	// The amount of time to wait between the lock renewals
	MySQLLockRenewInterval = 5 * time.Second

	// MySQLLockPrefix is the prefix used to mark MySQL records
	// as locks. This prefix causes them not to be returned by
	// List operations.
	MySQLLockPrefix = "_"
	// MySQLLockRetryInterval is the amount of time to wait
	// if a lock fails before trying again.
	MySQLLockRetryInterval = time.Second
	// MySQLWatchRetryMax is the number of times to re-try a
	// failed watch before signaling that leadership is lost.
	MySQLWatchRetryMax = 5
	// MySQLWatchRetryInterval is the amount of time to wait
	// if a watch fails before trying again.
	MySQLWatchRetryInterval = 5 * time.Second
)

// MySQLBackend is a physical backend that stores data
// within MySQL database.
type MySQLBackend struct {
	dbTable    string
	client     *sql.DB
	statements map[string]*sql.Stmt
	haEnabled  bool
	logger     log.Logger
	permitPool *physical.PermitPool
}

type MySQLLock struct {
	backend            *MySQLBackend
	value, key         string
	identity           string
	held               bool
	lock               sync.Mutex
	renewInterval      time.Duration
	ttl                time.Duration
	watchRetryInterval time.Duration
}

// NewMySQLBackend constructs a MySQL backend using the given API client and
// server address and credential for accessing mysql database.
func NewMySQLBackend(conf map[string]string, logger log.Logger) (physical.Backend, error) {
	var err error

	// Get the MySQL credentials to perform read/write operations.
	username, ok := conf["username"]
	if !ok || username == "" {
		return nil, fmt.Errorf("missing username")
	}
	password, ok := conf["password"]
	if !ok || username == "" {
		return nil, fmt.Errorf("missing password")
	}

	// Get or set MySQL server address. Defaults to localhost and default port(3306)
	address, ok := conf["address"]
	if !ok {
		address = "127.0.0.1:3306"
	}

	// Get the MySQL database and table details.
	database, ok := conf["database"]
	if !ok {
		database = "vault"
	}
	table, ok := conf["table"]
	if !ok {
		table = "vault"
	}
	dbTable := database + "." + table
	dbLockTable := dbTable + "_lock"

	haEnabled := os.Getenv("MYSQL_HA_ENABLED")
	if haEnabled == "" {
		haEnabled = conf["ha_enabled"]
	}
	haEnabledBool, _ := strconv.ParseBool(haEnabled)

	maxParStr, ok := conf["max_parallel"]
	var maxParInt int
	if ok {
		maxParInt, err = strconv.Atoi(maxParStr)
		if err != nil {
			return nil, errwrap.Wrapf("failed parsing max_parallel parameter: {{err}}", err)
		}
		if logger.IsDebug() {
			logger.Debug("mysql: max_parallel set", "max_parallel", maxParInt)
		}
	} else {
		maxParInt = physical.DefaultParallelOperations
	}

	dsnParams := url.Values{}
	tlsCaFile, ok := conf["tls_ca_file"]
	if ok {
		if err := setupMySQLTLSConfig(tlsCaFile); err != nil {
			return nil, fmt.Errorf("failed register TLS config: %v", err)
		}

		dsnParams.Add("tls", mysqlTLSKey)
	}

	// Create MySQL handle for the database.
	dsn := username + ":" + password + "@tcp(" + address + ")/?" + dsnParams.Encode()
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to mysql: %v", err)
	}

	db.SetMaxOpenConns(maxParInt)

	// Create the required database if it doesn't exist.
	if _, err := db.Exec("CREATE DATABASE IF NOT EXISTS " + database); err != nil {
		return nil, fmt.Errorf("failed to create mysql database: %v", err)
	}

	// Create the required table if it doesn't exist.
	create_query := "CREATE TABLE IF NOT EXISTS " + dbTable +
		" (vault_key varbinary(512), vault_value mediumblob, PRIMARY KEY (vault_key))"
	if _, err := db.Exec(create_query); err != nil {
		return nil, fmt.Errorf("failed to create mysql table: %v", err)
	}

	// Create the required lock table if it doesn't exist.
	create_lock_query := "CREATE TABLE IF NOT EXISTS " + dbLockTable +
		" (vault_lock_key varbinary(512), vault_lock_identity varchar(255), vault_lock_expires datetime, PRIMARY KEY (vault_lock_key))"
	if _, err := db.Exec(create_lock_query); err != nil {
		return nil, fmt.Errorf("failed to create mysql lock table: %v", err)
	}

	// Setup the backend.
	m := &MySQLBackend{
		dbTable:    dbTable,
		client:     db,
		statements: make(map[string]*sql.Stmt),
		haEnabled:  haEnabledBool,
		logger:     logger,
		permitPool: physical.NewPermitPool(maxParInt),
	}

	// Prepare all the statements required
	statements := map[string]string{
		"put": "INSERT INTO " + dbTable +
			" VALUES( ?, ? ) ON DUPLICATE KEY UPDATE vault_value=VALUES(vault_value)",
		"get":    "SELECT vault_value FROM " + dbTable + " WHERE vault_key = ?",
		"delete": "DELETE FROM " + dbTable + " WHERE vault_key = ?",
		"list":   "SELECT vault_key FROM " + dbTable + " WHERE vault_key LIKE ?",
		"setLock": "INSERT INTO " + dbLockTable +
			" VALUES( ?, ?, ? ) ON DUPLICATE KEY UPDATE " +
			"vault_lock_identity=IF((vault_lock_identity = VALUES(vault_lock_identity) OR vault_lock_expires <= NOW()), VALUES(vault_lock_identity), vault_lock_identity), " +
			"vault_lock_expires=IF((vault_lock_identity = VALUES(vault_lock_identity) OR vault_lock_expires <= NOW()), VALUES(vault_lock_expires), vault_lock_expires)",
		"getLock":    "SELECT vault_lock_identity FROM " + dbLockTable + " WHERE vault_lock_key = ?",
		"deleteLock": "DELETE FROM " + dbLockTable + " WHERE vault_lock_key = ?",
	}
	for name, query := range statements {
		if err := m.prepare(name, query); err != nil {
			return nil, err
		}
	}

	return m, nil
}

// prepare is a helper to prepare a query for future execution
func (m *MySQLBackend) prepare(name, query string) error {
	stmt, err := m.client.Prepare(query)
	if err != nil {
		return fmt.Errorf("failed to prepare '%s': %v", name, err)
	}
	m.statements[name] = stmt
	return nil
}

// Put is used to insert or update an entry.
func (m *MySQLBackend) Put(entry *physical.Entry) error {
	defer metrics.MeasureSince([]string{"mysql", "put"}, time.Now())

	m.permitPool.Acquire()
	defer m.permitPool.Release()

	_, err := m.statements["put"].Exec(entry.Key, entry.Value)
	if err != nil {
		return err
	}
	return nil
}

// Get is used to fetch and entry.
func (m *MySQLBackend) Get(key string) (*physical.Entry, error) {
	defer metrics.MeasureSince([]string{"mysql", "get"}, time.Now())

	m.permitPool.Acquire()
	defer m.permitPool.Release()

	var result []byte
	err := m.statements["get"].QueryRow(key).Scan(&result)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	ent := &physical.Entry{
		Key:   key,
		Value: result,
	}
	return ent, nil
}

// Delete is used to permanently delete an entry
func (m *MySQLBackend) Delete(key string) error {
	defer metrics.MeasureSince([]string{"mysql", "delete"}, time.Now())

	m.permitPool.Acquire()
	defer m.permitPool.Release()

	_, err := m.statements["delete"].Exec(key)
	if err != nil {
		return err
	}
	return nil
}

// List is used to list all the keys under a given
// prefix, up to the next prefix.
func (m *MySQLBackend) List(prefix string) ([]string, error) {
	defer metrics.MeasureSince([]string{"mysql", "list"}, time.Now())

	m.permitPool.Acquire()
	defer m.permitPool.Release()

	// Add the % wildcard to the prefix to do the prefix search
	likePrefix := prefix + "%"
	rows, err := m.statements["list"].Query(likePrefix)
	if err != nil {
		return nil, fmt.Errorf("failed to execute statement: %v", err)
	}

	var keys []string
	for rows.Next() {
		var key string
		err = rows.Scan(&key)
		if err != nil {
			return nil, fmt.Errorf("failed to scan rows: %v", err)
		}

		key = strings.TrimPrefix(key, prefix)
		if i := strings.Index(key, "/"); i == -1 {
			// Add objects only from the current 'folder'
			keys = append(keys, key)
		} else if i != -1 {
			// Add truncated 'folder' paths
			keys = strutil.AppendIfMissing(keys, string(key[:i+1]))
		}
	}

	sort.Strings(keys)
	return keys, nil
}

// LockWith is used for mutual exclusion based on the given key.
func (d *MySQLBackend) LockWith(key, value string) (physical.Lock, error) {
	return &MySQLLock{
		backend:            d,
		key:                pkgPath.Join(pkgPath.Dir(key), MySQLLockPrefix+pkgPath.Base(key)),
		identity:           value,
		renewInterval:      MySQLLockRenewInterval,
		ttl:                MySQLLockTTL,
		watchRetryInterval: MySQLWatchRetryInterval,
	}, nil
}

// Lock tries to acquire the lock by repeatedly trying to create
// a record in the MySQL table. It will block until either the
// stop channel is closed or the lock could be acquired successfully.
// The returned channel will be closed once the lock is deleted or
// changed in the MySQL table.
func (l *MySQLLock) Lock(stopCh <-chan struct{}) (doneCh <-chan struct{}, retErr error) {
	l.lock.Lock()
	defer l.lock.Unlock()
	if l.held {
		return nil, fmt.Errorf("lock already held")
	}

	done := make(chan struct{})
	// close done channel even in case of error
	defer func() {
		if retErr != nil {
			close(done)
		}
	}()

	var (
		stop    = make(chan struct{})
		success = make(chan struct{})
		errors  = make(chan error)
		leader  = make(chan struct{})
	)
	// try to acquire the lock asynchronously
	go l.tryToLock(stop, success, errors)

	select {
	case <-success:
		l.held = true
		// after acquiring it successfully, we must renew the lock periodically,
		// and watch the lock in order to close the leader channel
		// once it is lost.
		go l.periodicallyRenewLock(leader)
		go l.watch(leader)
	case retErr = <-errors:
		close(stop)
		return nil, retErr
	case <-stopCh:
		close(stop)
		return nil, nil
	}

	return leader, retErr
}

// Unlock releases the lock by deleting the lock record from the
// MySQL table.
func (l *MySQLLock) Unlock() error {
	l.lock.Lock()
	defer l.lock.Unlock()
	if !l.held {
		return nil
	}

	l.held = false

	defer metrics.MeasureSince([]string{"mysql", "delete"}, time.Now())

	m := l.backend
	m.permitPool.Acquire()
	defer m.permitPool.Release()

	_, err := l.backend.statements["deleteLock"].Exec(l.key)

	return err
}

// Value checks whether or not the lock is held by any instance of MySQLLock,
// including this one, and returns the current value.
func (l *MySQLLock) Value() (bool, string, error) {
	var identity string
	err := l.backend.statements["getLock"].QueryRow(l.key).Scan(&identity)
	if err != nil {
		return false, "", err
	}
	if identity == "" {
		return false, "", nil
	}

	return true, identity, nil
}

func (d *MySQLBackend) HAEnabled() bool {
	return d.haEnabled
}

// Attempts to put/update the mysql item using condition expressions to
// evaluate the TTL.
func (l *MySQLLock) writeItem() error {
	expires := time.Now().Add(l.ttl).Format(time.RFC3339)

	resp, err := l.backend.statements["setLock"].Exec(l.key, l.identity, expires)
	if err != nil {
		return err
	}

	result, err := resp.RowsAffected()
	if err != nil {
		return err
	}
	if result == 0 {
		err = fmt.Errorf("conditional check failed")
	}

	return err
}

// tryToLock tries to create a new item in MySQL
// every `MySQLLockRetryInterval`. As long as the item
// cannot be created (because it already exists), it will
// be retried. If the operation fails due to an error, it
// is sent to the errors channel.
// When the lock could be acquired successfully, the success
// channel is closed.
func (l *MySQLLock) tryToLock(stop, success chan struct{}, errors chan error) {
	ticker := time.NewTicker(MySQLLockRetryInterval)

	for {
		select {
		case <-stop:
			ticker.Stop()
		case <-ticker.C:
			err := l.writeItem()
			if err != nil {
				if err.Error() != "conditional check failed" {
					errors <- err
					return
				}
			} else {
				ticker.Stop()
				close(success)
				return
			}
		}
	}
}

func (l *MySQLLock) periodicallyRenewLock(done chan struct{}) {
	ticker := time.NewTicker(l.renewInterval)
	for {
		select {
		case <-ticker.C:
			l.writeItem()
		case <-done:
			ticker.Stop()
			return
		}
	}
}

// watch checks whether the lock has changed in the
// MySQL table and closes the leader channel if so.
// The interval is set by `MySQLWatchRetryInterval`.
// If an error occurs during the check, watch will retry
// the operation for `MySQLWatchRetryMax` times and
// close the leader channel if it can't succeed.
func (l *MySQLLock) watch(lost chan struct{}) {
	retries := MySQLWatchRetryMax

	ticker := time.NewTicker(l.watchRetryInterval)
WatchLoop:
	for {
		select {
		case <-ticker.C:
			var resp string
			err := l.backend.statements["getLock"].QueryRow(l.key).Scan(&resp)
			if err != nil {
				retries--
				if retries == 0 {
					break WatchLoop
				}
				continue
			}
			if resp == "" || resp != l.identity {
				break WatchLoop
			}
		}
	}

	close(lost)
}

// Establish a TLS connection with a given CA certificate
// Register a tsl.Config associted with the same key as the dns param from sql.Open
// foo:bar@tcp(127.0.0.1:3306)/dbname?tls=default
func setupMySQLTLSConfig(tlsCaFile string) error {
	rootCertPool := x509.NewCertPool()

	pem, err := ioutil.ReadFile(tlsCaFile)
	if err != nil {
		return err
	}

	if ok := rootCertPool.AppendCertsFromPEM(pem); !ok {
		return err
	}

	err = mysql.RegisterTLSConfig(mysqlTLSKey, &tls.Config{
		RootCAs: rootCertPool,
	})
	if err != nil {
		return err
	}

	return nil
}
