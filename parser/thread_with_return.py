from threading import Thread


class ThreadWithReturn(Thread):
    def __init__(self, group=None, target=None, name=None, args=(), kwargs={}):
        Thread.__init__(self, group, target, name, args, kwargs)
        self._return = None

    def run(self):
        if self._target is not None:
            self._return = self._target(self._args, self._kwargs)

    def join(self, *args):
        if args:
            Thread.join(self, args)
        Thread.join(self)
        return self._return
