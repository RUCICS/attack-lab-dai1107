# Problem 4 Solution
# The program asks 3 questions.
# 1. "what is your name?" -> Input anything (e.g., "daimingqiu")
# 2. "do you like ics?" -> Input anything (e.g., "yes")
# 3. "if you give me enough yuanshi..." -> Input -1

# Why -1?
# The function `func` contains a loop logic that compares the input argument against 0xfffffffe.
# If input is -1 (0xffffffff), it enters a loop that eventually decrements a copy of the argument.
# After the loop, it checks if the decremented value is 1.
# -1 (input) - (-2) (loop iterations implicitly) = 1.
# This satisfies the condition to call the success function `func1`.

payload = b"daimingqiu\nyes\n-1\n"

with open('ans4.txt', 'wb') as f:
    f.write(payload)

print("ans4.txt generated.")
