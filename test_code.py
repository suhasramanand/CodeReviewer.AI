def add(a, b):
    """
    A simple function to add two numbers.
    """
    return a + b

# Test case to validate the add function
if __name__ == "__main__":
    result = add(2, 3)
    if result == 5:
        print("Test passed!")
    else:
        print("Test failed!")
