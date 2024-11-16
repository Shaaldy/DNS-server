import subprocess

# Список команд для тестирования DNS-сервера
commands = [
    "chcp 437",

    "nslookup -type=ptr amazon.com 127.0.0.1",

    "nslookup -type=ptr vk.com 127.0.0.1",

    "nslookup -type=ptr yandex.ru 127.0.0.1",

    "nslookup -type=ptr ok.ru 127.0.0.1",

    "nslookup -type=ptr youtube.com 127.0.0.1",

    "nslookup -type=ptr google.com 127.0.0.1",

    "nslookup -type=ptr faceit.com 127.0.0.1",

    "nslookup wikipedia.org 127.0.0.1"
]


def run_command(command):
    try:
        result = subprocess.run(command, shell=True, text=True, capture_output=True, timeout=30)
        return result.stdout
    except subprocess.TimeoutExpired:
        return f"Command timed out: {command}"


def main():
    with open("test.txt", "w") as f:
        for command in commands:
            print(f"Running command: {command}")
            output = run_command(command)
            f.write(f"Command: {command}\n")
            f.write(output)
            f.write("\n" + "=" * 80 + "\n")


if __name__ == "__main__":
    main()
