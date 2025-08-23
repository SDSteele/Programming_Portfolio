import json
import os
from colorama import Fore, Style, init

init(autoreset=True)

TODO_FILE = 'todo.json'

def load_tasks():
    if os.path.exists(TODO_FILE):
        with open(TODO_FILE, 'r') as file:
            return json.load(file)
    return []

def save_tasks(tasks):
    with open(TODO_FILE, 'w') as file:
        json.dump(tasks, file, indent=4)

def list_tasks(tasks):
    if not tasks:
        print(Fore.YELLOW + "🎉 No tasks found!")
    else:
        print(Fore.CYAN + "\nYour Tasks:")
        for idx, task in enumerate(tasks, 1):
            status = Fore.GREEN + "✅" if task['done'] else Fore.RED + "❌"
            print(f"{Fore.MAGENTA}{idx}. {status} {task['title']}")

def add_task(tasks):
    title = input(Fore.BLUE + "Enter task title: ")
    tasks.append({'title': title, 'done': False})
    print(Fore.GREEN + "✔️ Task added!")

def complete_task(tasks):
    list_tasks(tasks)
    try:
        idx = int(input(Fore.BLUE + "\nEnter task number to mark complete: ")) - 1
        if 0 <= idx < len(tasks):
            tasks[idx]['done'] = True
            print(Fore.GREEN + "🎯 Task marked as complete!")
        else:
            print(Fore.RED + "Invalid number.")
    except ValueError:
        print(Fore.RED + "Please enter a valid number.")

def menu():
    tasks = load_tasks()
    while True:
        print(Fore.CYAN + "\n--- TO-DO LIST MENU ---")
        print("1. View tasks")
        print("2. Add task")
        print("3. Complete task")
        print("4. Quit")
        choice = input(Fore.YELLOW + "Choose an option: ")

        if choice == '1':
            list_tasks(tasks)
        elif choice == '2':
            add_task(tasks)
        elif choice == '3':
            complete_task(tasks)
        elif choice == '4':
            save_tasks(tasks)
            print(Fore.CYAN + "👋 Goodbye!")
            break
        else:
            print(Fore.RED + "Invalid choice. Try again.")

if __name__ == "__main__":
    menu()
