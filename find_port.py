"""Print the first free localhost TCP port starting at 8501. Used by the launcher."""
import socket

port = 8501
while True:
    s = socket.socket()
    try:
        s.bind(("localhost", port))
        s.close()
        break
    except OSError:
        s.close()
        port += 1
print(port)
