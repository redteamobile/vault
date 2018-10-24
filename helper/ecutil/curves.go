package ecutil

import (
	"crypto/elliptic"
	"math/big"
	"sync"
)

var (
	once     sync.Once
	fRP256v1 *elliptic.CurveParams
)

func initAll() {
	initFRP256v1()
}

func initFRP256v1() {
	fRP256v1 = &elliptic.CurveParams{Name: "FRP256v1"}
	fRP256v1.P, _ = new(big.Int).SetString("F1FD178C0B3AD58F10126DE8CE42435B3961ADBCABC8CA6DE8FCF353D86E9C03", 16)
	fRP256v1.N, _ = new(big.Int).SetString("F1FD178C0B3AD58F10126DE8CE42435B53DC67E140D2BF941FFDD459C6D655E1", 16)
	fRP256v1.B, _ = new(big.Int).SetString("EE353FCA5428A9300D4ABA754A44C00FDFEC0C9AE4B1A1803075ED967B7BB73F", 16)
	fRP256v1.Gx, _ = new(big.Int).SetString("B6B3D4C356C139EB31183D4749D423958C27D2DCAF98B70164C97A2DD98F5CFF", 16)
	fRP256v1.Gy, _ = new(big.Int).SetString("6142E0F7C8B204911F9271F0F3ECEF8C2701C307E8E4C9E183115A1554062CFB", 16)
	fRP256v1.BitSize = 256
}

// FRP256v1 returns a Curve which implements FRP256v1 (see https://www.legifrance.gouv.fr/affichTexte.do?cidTexte=JORFTEXT000024668816)
func FRP256v1() elliptic.Curve {
	once.Do(initAll)
	return fRP256v1
}
