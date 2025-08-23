import json
import os

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
        print("🎉 No tasks found!")
    for idx, task in enumerate(tasks, 1):
        status = "✅" if task['done'] else "❌"
        print(f"{idx}. {status} {task['title']}")

def add_task(tasks):
    title = input("Enter task title: ")
    tasks.append({'title': title, 'done': False})
    print("Task added!")

def complete_task(tasks):
    list_tasks(tasks)
    try:
        idx = int(input("Enter task number to mark complete: ")) - 1
        if 0 <= idx < len(tasks):
            tasks[idx]['done'] = True
            print("Marked as complete!")
        else:
            print("Invalid number.")
    except ValueError:
        print("Please enter a valid number.")

def menu():
    tasks = load_tasks()
    while True:
        print("\n--- TO-DO LIST ---")
        print("1. View tasks")
        print("2. Add task")
        print("3. Complete task")
        print("4. Quit")
        choice = input("Choose an option: ")

        if choice == '1':
            list_tasks(tasks)
        elif choice == '2':
            add_task(tasks)
        elif choice == '3':
            complete_task(tasks)
        elif choice == '4':
            save_tasks(tasks)
            print("Goodbye!")
            break
        else:
            print("Invalid choice. Try again.")

if __name__ == "__main__":
    menu()
