import subprocess

# Список команд для тестирования DNS-сервера
commands = [
    "chcp 437",
    "nslookup -debug amazon.com 127.0.0.1",
    "nslookup -type=NS amazon.com 127.0.0.1",
    "nslookup -type=A amazon.com 127.0.0.1",
    "nslookup -type=PTR amazon.com 127.0.0.1",
    "nslookup -type=AAAA amazon.com 127.0.0.1",

    "nslookup vk.com 127.0.0.1",
    "nslookup -type=NS vk.com 127.0.0.1",
    "nslookup -type=A vk.com 127.0.0.1",
    "nslookup -type=PTR vk.com 127.0.0.1",
    "nslookup -type=AAAA vk.com 127.0.0.1",

    "nslookup yandex.ru 127.0.0.1",
    "nslookup -type=NS yandex.ru 127.0.0.1",
    "nslookup -type=A yandex.ru 127.0.0.1",
    "nslookup -type=PTR yandex.ru 127.0.0.1",
    "nslookup -type=AAAA yandex.ru 127.0.0.1",

    "nslookup ok.ru 127.0.0.1",
    "nslookup -type=NS ok.ru 127.0.0.1",
    "nslookup -type=A ok.ru 127.0.0.1",
    "nslookup -type=PTR ok.ru 127.0.0.1",
    "nslookup -type=AAAA ok.ru 127.0.0.1",

    "nslookup youtube.com 127.0.0.1",
    "nslookup -type=NS youtube.com 127.0.0.1",
    "nslookup -type=A youtube.com 127.0.0.1",
    "nslookup -type=PTR youtube.com 127.0.0.1",
    "nslookup -type=AAAA youtube.com 127.0.0.1",

    "nslookup google.com 127.0.0.1",
    "nslookup -type=NS google.com 127.0.0.1",
    "nslookup -type=A google.com 127.0.0.1",
    "nslookup -type=PTR google.com 127.0.0.1",
    "nslookup -type=AAAA google.com 127.0.0.1",

    "nslookup faceit.com 127.0.0.1",
    "nslookup -type=NS faceit.com 127.0.0.1",
    "nslookup -type=A faceit.com 127.0.0.1",
    "nslookup -type=PTR faceit.com 127.0.0.1",
    "nslookup -type=AAAA faceit.com 127.0.0.1",

    "nslookup -debug wikipedia.org 127.0.0.1"
]


def run_command(command):
    try:
        result = subprocess.run(command, shell=True, text=True, capture_output=True, timeout=30)
        return result.stdout
    except subprocess.TimeoutExpired:
        return f"Command timed out: {command}"


def main():
    with open("dns_test_results.txt", "w") as f:
        for command in commands:
            print(f"Running command: {command}")
            output = run_command(command)
            f.write(f"Command: {command}\n")
            f.write(output)
            f.write("\n" + "=" * 80 + "\n")


if __name__ == "__main__":
    main()
