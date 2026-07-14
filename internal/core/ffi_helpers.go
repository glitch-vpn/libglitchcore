package core

func runFFICall(fn func() int32) int32 {
	inFFICall.Store(true)
	defer inFFICall.Store(false)
	return fn()
}
