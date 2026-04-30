package mathy

func Add(a, b int) int {
	return a + b
}

func Multiply(a, b int) int {
	total := 0
	for i := 0; i < b; i++ {
		total += a
	}
	return total
}
