#!/usr/bin/env python3


def quickSort(arr, left, right):
    if left < right:
        pivot = partition(arr, left, right)
        quickSort(arr, left, pivot - 1)
        quickSort(arr, pivot, right)
    return arr


def partition(arr, left, right):
    pivot = arr[(left + right) // 2]
    while left <= right:
        while arr[left] < pivot:
            left += 1
        while arr[right] > pivot:
            right -= 1
        if left <= right:
            (arr[left], arr[right]) = (arr[right], arr[left])
            left += 1
            right -= 1
    return left


a = [1, 4, 7, 4, 2, 6, 5, 3]
print(quickSort(a, 0, len(a) - 1))
