package main

import (
	"fmt"
	"reflect"
)

// String representation of an aribtrary reflect value field
func fieldString(v reflect.Value, name string) string {
	val := reflect.Indirect(v)
	if !val.IsValid() {
		return ""
	}

	val = val.FieldByName(name)
	if !val.IsValid() {
		return ""
	}

	return fmt.Sprintf("%s", val)
}

// Variadic fanin function
func fanin(inputs ...<-chan NGResult) <-chan NGResult {
	agg := make(chan NGResult)

	for _, ch := range inputs {
		go func(c <-chan NGResult) {
			for msg := range c {
				agg <- msg
			}
		}(ch)
	}

	return agg
}
