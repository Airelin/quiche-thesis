### These lines are generating a textfile with a lot of lines
for i in range(0,400000):
    f = open("Textfile.txt", "a")
    f.write("Line" + str(i)+ ", Line" + str(i)+ ", Line" + str(i)+ ", Line" + str(i)+ ", Line" + str(i)+ ", Line" + str(i)+ ", Line" + str(i)+ ", Line" + str(i)+ ", Line" + str(i)+ ", Line" + str(i)+ "\n")
f.close()