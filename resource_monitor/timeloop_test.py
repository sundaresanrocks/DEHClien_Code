from timeloop import Timeloop
from datetime import timedelta

tl = Timeloop()
class FileToMove:

    def start(self):
        tl.start()

    @tl.job(interval=timedelta(seconds=2))
    def timedMethod():
        print("hello", flush=True)

if __name__ == "__main__":

    ob1 = FileToMove()
    ob1.start()
    input("Press any key to exit")
