def y_n_choice():
    while True:
        try:
            user_input = input("Enter 'yes' to continue or 'no' to skip: ")

            if user_input is None:
                print("Error: Result is None.")
                return

            user_input = user_input.lower()
            if user_input not in ['yes', 'y', 'no', 'n', '']:
                raise ValueError("Invalid input, please enter 'yes' or 'no'.")

            return user_input
        except ValueError as ve:
            print("Error:", ve)
        except TypeError as ve:
            print("Error:", ve)
        except AttributeError as ve:
            print("Error:", ve)
