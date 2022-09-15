def add(a, b):
    return a + b

input1 = input("Enter a value for a: ")
input2 = input("Enter a value for b: ")

sum = add(int(input1), int(input2))
print(f"{input1} + {input2} = {sum}")
