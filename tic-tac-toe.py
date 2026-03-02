def board(board_list):
    print(f"{board_list[0]}|{board_list[1]}|{board_list[2]}")
    print("------")
    print(f"{board_list[3]}|{board_list[4]}|{board_list[5]}")
    print("------")
    print(f"{board_list[6]}|{board_list[7]}|{board_list[8]}")
    print()

def board_index():
    print("1|2|3")
    print("-------")
    print("4|5|6")
    print("-------")
    print("7|8|9")
    print()

def fill_board(board_list,index):
    board_list[index] = symbol

def win_condition(board_list,symbol):
    if board_list[0] == board_list[1] == board_list[2] == symbol:
        return True
    elif board_list[3] == board_list[4] == board_list[5] == symbol:
        return True
    elif board_list[6] == board_list[7] == board_list[8] == symbol:
        return True
    elif board_list[0] == board_list[3] == board_list[6] == symbol:
        return True
    elif board_list[1] == board_list[4] == board_list[7] == symbol:
        return True
    elif board_list[2] == board_list[5] == board_list[8] == symbol:
        return True
    elif board_list[0] == board_list[4] == board_list[8] == symbol:
        return True
    elif board_list[2] == board_list[4] == board_list[6] == symbol:
        return True
    else:
        return False

player1 = input("Enter the name of Player 1: ")
player2 = input("Enter the name of Player 2: ")

a = [" "," "," "," "," "," "," "," "," "," "," "]
filled  = []

symbol = "O"
board_index()
board(a)



for i in range(1,10):

    if symbol == "O":
        symbol = "X"
        print(f"{player1}'s turn")
    else:
        symbol = "O"
        print(f"{player2}'s turn")

    placement = int(input("Enter the index to choose: "))
    if placement < 1 or placement > 9:
        print("Invalid index")
        continue

    if placement in filled:
        print("Index already filled")
        continue
    filled.append(placement)

    fill_board(a,placement-1)
    board(a)

    if win_condition(a, symbol):
        if symbol == "X":
            print(f"{player1} wins!")
        else:
            print(f"{player2} wins!")

if not win_condition(a, symbol):
    print("draw")
