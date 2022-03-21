#!/usr/bin/env python3

import sys

# Extended Euclidean algorithm
def egcd(a, b, i=0):
    print("| " * i + f"egcd({a}, {b})")
    if a == 0:
        print("| " * i + f"return (b, 0) = ({b}, 0)")
        return b, 0, 1
    else:
        print("| " * i + f"egcd(b % a, a) = egcd({b} % {a}, {a}) = egcd({b % a}, {a})")
        gcd, x, y = egcd(b % a, a, i + 1)
        print(
            "| " * i
            + f"return (gcd, y - (b // a) * x, x) = ({gcd}, {y - (b // a) * x}, {x})"
        )
        return gcd, y - (b // a) * x, x


if __name__ == "__main__":
    if len(sys.argv) > 2:
        a, b = int(sys.argv[1]), int(sys.argv[2])
    else:
        a, b = 30, 50
    gcd, x, y = egcd(a, b)
    print(f"egcd({a}, {b}) = ({gcd}, {x}, {y})")
