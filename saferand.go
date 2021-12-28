// Package saferand implements a cryptographically secure
// (mostly) drop-in replacement for exp/rand (and math/rand).
//
//    import rand "github.com/ericlagergren/saferand"
//
// All Seed functions and methods are no-ops.
package saferand

import (
	"crypto/rand"
	"encoding/binary"
	"math"

	exprand "golang.org/x/exp/rand"
)

var defaultRand = exprand.New(NewSource())

func ExpFloat64() float64                { return defaultRand.ExpFloat64() }
func Float32() float32                   { return defaultRand.Float32() }
func Float64() float64                   { return defaultRand.Float64() }
func Int() int                           { return defaultRand.Int() }
func Int31() int32                       { return defaultRand.Int31() }
func Int31n(n int32) int32               { return defaultRand.Int31n(n) }
func Int63() int64                       { return defaultRand.Int63() }
func Int63n(n int64) int64               { return defaultRand.Int63n(n) }
func Intn(n int) int                     { return defaultRand.Intn(n) }
func NormFloat64() float64               { return defaultRand.NormFloat64() }
func Perm(n int) []int                   { return defaultRand.Perm(n) }
func Read(p []byte) (int, error)         { return rand.Read(p) }
func Seed(_ uint64)                      {}
func Shuffle(n int, swap func(i, j int)) { defaultRand.Shuffle(n, swap) }
func Uint32() uint32                     { return defaultRand.Uint32() }
func Uint64() uint64                     { return defaultRand.Uint64() }

type Rand = exprand.Rand

// New returns a Rand that generated cryptographically secure
// random values.
func New() *Rand {
	return exprand.New(NewSource())
}

type Source = exprand.Source

// ExpSource implements Source.
type ExpSource struct{}

var _ exprand.Source = ExpSource{}

// NewSource returns a cryptographically secure Source.
//
// Unlike math/rand, the returned Source is safe for concurrent
// use by multiple goroutines.
func NewSource() exprand.Source {
	return ExpSource{}
}

func (ExpSource) Seed(_ uint64) {}

func (ExpSource) Int63() int64 {
	buf := make([]byte, 8)
	for i := 0; ; i++ {
		if _, err := rand.Read(buf); err != nil {
			panic(err)
		}
		const (
			mask = 1<<7 - 1
		)
		buf[0] &= byte(mask)
		x := binary.BigEndian.Uint64(buf)
		if x < math.MaxInt64 {
			return int64(x)
		}
	}
}

func (ExpSource) Uint64() uint64 {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}
	return binary.LittleEndian.Uint64(buf)
}

type Zipf = exprand.Zipf

func NewZipf(r *Rand, s float64, v float64, imax uint64) *Zipf {
	return exprand.NewZipf(r, s, v, imax)
}
