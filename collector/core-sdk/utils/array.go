// Licensed to the Apache Software Foundation (ASF) under one or more
// contributor license agreements.  See the NOTICE file distributed with
// this work for additional information regarding copyright ownership.
// The ASF licenses this file to You under the Apache License, Version 2.0
// (the "License"); you may not use this file except in compliance with
// the License.  You may obtain a copy of the License at
//
//  http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package utils

func Contains(arr []string, ele string) bool {
	for _, a := range arr {
		if a == ele {
			return true
		}
	}
	return false
}

func ContainsInt(arr []int, ele int) bool {
	for _, a := range arr {
		if a == ele {
			return true
		}
	}
	return false
}

// IsContain Compare whether l1 contains all the elements in l2
func IsContain(items interface{}, item interface{}) bool {
	switch items.(type) {
	case []int:
		intArr := items.([]int)
		for _, value := range intArr {
			if value == item.(int) {
				return true
			}
		}
	case []string:
		strArr := items.([]string)
		for _, value := range strArr {
			if value == item.(string) {
				return true
			}
		}
	default:
		return false
	}
	return false
}

// IntersectList Get the intersection of multiple slices
func IntersectList(list1 []string, list2 []string) []string {
	var list [][]string
	list = append(list, list1)
	list = append(list, list2)
	return Intersect(list)
}

// Intersect Get the intersection of multiple slices
func Intersect(lists [][]string) []string {
	var inter []string
	mp := make(map[string]int)
	l := len(lists)

	if l == 0 {
		return make([]string, 0)
	}
	if l == 1 {
		for _, s := range lists[0] {
			if _, ok := mp[s]; !ok {
				mp[s] = 1
				inter = append(inter, s)
			}
		}
		return inter
	}

	for _, s := range lists[0] {
		if _, ok := mp[s]; !ok {
			mp[s] = 1
		}
	}

	for _, list := range lists[1 : l-1] {
		for _, s := range list {
			if _, ok := mp[s]; ok {
				mp[s]++
			}
		}
	}

	for _, s := range lists[l-1] {
		if _, ok := mp[s]; ok {
			if mp[s] == l-1 {
				inter = append(inter, s)
			}
		}
	}

	return inter
}

// ArrayToString Convert array to string
func ArrayToString(arr []string) string {
	var result string
	for _, i := range arr {
		result += i + ","
	}
	return result
}

// Remove Delete the specified element from the array
func Remove(slice []string, elem string) []string {
	for i, v := range slice {
		if v == elem {
			// 利用切片的切割操作删除指定元素
			return append(slice[:i], slice[i+1:]...)
		}
	}
	return slice
}

// UniqueList Deduplication while preserving original order
func UniqueList(input []string) []string {
	counts := make(map[string]bool)
	var result []string

	for _, item := range input {
		if !counts[item] {
			counts[item] = true
			result = append(result, item)
		}
	}

	return result
}

// Filter 返回切片中满足断言函数的所有元素
func Filter[T any](slice []T, predicate func(T) bool) []T {
	result := make([]T, 0, len(slice))
	for _, item := range slice {
		if predicate(item) {
			result = append(result, item)
		}
	}
	return result
}

func Exclude[T comparable](slice, exclude []T) []T {
	excludeMap := make(map[T]struct{})
	for _, item := range exclude {
		excludeMap[item] = struct{}{}
	}

	var result []T
	for _, item := range slice {
		if _, exists := excludeMap[item]; !exists {
			result = append(result, item)
		}
	}
	return result
}
