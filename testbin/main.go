package main

import "fmt"

func add(a, b int) int { return a + b }
func sub(a, b int) int { return a - b }
func greet(name string) { fmt.Println("Hello,", name) }

func main() {
	x := add(10, 20)
	y := sub(100, 50)
	greet("world")
	fmt.Println(x, y)
}
