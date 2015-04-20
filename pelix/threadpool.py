#!/usr/bin/env python
# -- Content-Encoding: UTF-8 --
"""
Pelix Utilities: Cached thread pool

:author: Thomas Calmant
:copyright: Copyright 2015, isandlaTech
:license: Apache License 2.0
:version: 0.6.1

..

    Copyright 2015 isandlaTech

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
"""

# Documentation strings format
__docformat__ = "restructuredtext en"

# Module version
__version_info__ = (0, 6, 1)
__version__ = ".".join(str(x) for x in __version_info__)

# ------------------------------------------------------------------------------

# Pelix
import pelix.utilities

# Standard library
import logging
import threading

try:
    # Python 3
    # pylint: disable=F0401
    import queue
except ImportError:
    # Python 2
    # pylint: disable=F0401
    import Queue as queue

# ------------------------------------------------------------------------------


class FutureResult(object):
    """
    An object to wait for the result of a threaded execution
    """
    def __init__(self, logger=None):
        """
        Sets up the FutureResult object

        :param logger: The Logger to use in case of error (optional)
        """
        self._logger = logger or logging.getLogger(__name__)
        self._done_event = pelix.utilities.EventData()
        self.__callback = None
        self.__extra = None

    def __notify(self):
        """
        Notify the given callback about the result of the execution
        """
        if self.__callback is not None:
            try:
                self.__callback(self._done_event.data,
                                self._done_event.exception,
                                self.__extra)
            except Exception as ex:
                self._logger.exception("Error calling back method: %s", ex)

    def set_callback(self, method, extra=None):
        """
        Sets a callback method, called once the result has been computed or in
        case of exception.

        The callback method must have the following signature:
        ``callback(result, exception, extra)``.

        :param method: The method to call back in the end of the execution
        :param extra: Extra parameter to be given to the callback method
        """
        self.__callback = method
        self.__extra = extra
        if self._done_event.is_set():
            # The execution has already finished
            self.__notify()

    def execute(self, method, args, kwargs):
        """
        Execute the given method and stores its result.
        The result is considered "done" even if the method raises an exception

        :param method: The method to execute
        :param args: Method positional arguments
        :param kwargs: Method keyword arguments
        :raise Exception: The exception raised by the method
        """
        # Normalize arguments
        if args is None:
            args = []

        if kwargs is None:
            kwargs = {}

        try:
            # Call the method
            result = method(*args, **kwargs)
        except Exception as ex:
            # Something went wrong: propagate to the event and to the caller
            self._done_event.raise_exception(ex)
            raise
        else:
            # Store the result
            self._done_event.set(result)
        finally:
            # In any case: notify the call back (if any)
            self.__notify()

    def done(self):
        """
        Returns True if the job has finished, else False
        """
        return self._done_event.is_set()

    def result(self, timeout=None):
        """
        Waits up to timeout for the result the threaded job.
        Returns immediately the result if the job has already been done.

        :param timeout: The maximum time to wait for a result (in seconds)
        :raise OSError: The timeout raised before the job finished
        :raise Exception: The exception encountered during the call, if any
        """
        if self._done_event.wait(timeout):
            return self._done_event.data
        else:
            raise OSError("Timeout raised")

# ------------------------------------------------------------------------------


class ThreadPool(object):
    """
    Executes the tasks stored in a FIFO in a thread pool
    """
    def __init__(self, max_threads, min_threads=1, queue_size=0, timeout=60,
                 logname=None):
        """
        Sets up the thread pool.

        Threads are kept alive 60 seconds (timeout argument).

        :param max_threads: Maximum size of the thread pool
        :param min_threads: Minimum size of the thread pool
        :param queue_size: Size of the task queue (0 for infinite)
        :param timeout: Queue timeout (in seconds, 60s by default)
        :param logname: Name of the logger
        :raise ValueError: Invalid number of threads
        """
        # Validate parameters
        try:
            max_threads = int(max_threads)
            if max_threads < 1:
                raise ValueError("Pool size must be greater than 0")
        except (TypeError, ValueError) as ex:
            raise ValueError("Invalid pool size: {0}".format(ex))

        try:
            min_threads = int(min_threads)
            if min_threads < 0:
                min_threads = 0
            elif min_threads > max_threads:
                min_threads = max_threads
        except (TypeError, ValueError) as ex:
            raise ValueError("Invalid pool size: {0}".format(ex))

        # The logger
        self._logger = logging.getLogger(logname or __name__)

        # The loop control event
        self._done_event = threading.Event()
        self._done_event.set()

        # The task queue
        try:
            queue_size = int(queue_size)
        except (TypeError, ValueError):
            # Not a valid integer
            queue_size = 0

        self._queue = queue.Queue(queue_size)
        self._timeout = timeout
        self.__lock = threading.RLock()

        # The thread pool
        self._min_threads = min_threads
        self._max_threads = max_threads
        self._threads = []

        # Thread count
        self._thread_id = 0

        # Current number of threads, active and alive
        self.__nb_threads = 0
        self.__nb_active_threads = 0

    def start(self):
        """
        Starts the thread pool. Does nothing if the pool is already started.
        """
        if not self._done_event.is_set():
            # Stop event not set: we're running
            return

        # Clear the stop event
        self._done_event.clear()

        # Compute the number of threads to start to handle pending tasks
        nb_pending_tasks = self._queue.qsize()
        if nb_pending_tasks > self._max_threads:
            nb_threads = self._max_threads
        elif nb_pending_tasks < self._min_threads:
            nb_threads = self._min_threads
        else:
            nb_threads = nb_pending_tasks

        # Create the threads
        for _ in range(nb_threads):
            self.__start_thread()

    def __start_thread(self):
        """
        Starts a new thread, if possible
        """
        with self.__lock:
            if self.__nb_threads >= self._max_threads:
                # Can't create more threads
                return False

            if self._done_event.is_set():
                # We're stopped: do nothing
                return False

            # Prepare thread and start it
            name = "{0}-{1}".format(self._logger.name, self._thread_id)
            self._thread_id += 1

            thread = threading.Thread(target=self.__run, name=name)
            thread.daemon = True
            self._threads.append(thread)
            thread.start()
            return True

    def stop(self):
        """
        Stops the thread pool. Does nothing if the pool is already stopped.
        """
        if self._done_event.is_set():
            # Stop event set: we're stopped
            return

        # Set the stop event
        self._done_event.set()

        with self.__lock:
            # Add something in the queue (to unlock the join())
            try:
                for _ in self._threads:
                    self._queue.put(self._done_event, True, self._timeout)
            except queue.Full:
                # There is already something in the queue
                pass

            # Copy the list of threads to wait for
            threads = self._threads[:]

        # Join threads outside the lock
        for thread in threads:
            while thread.is_alive():
                # Wait 3 seconds
                thread.join(3)
                if thread.is_alive():
                    # Thread is still alive: something might be wrong
                    self._logger.warning("Thread %s is still alive...",
                                         thread.name)

        # Clear storage
        del self._threads[:]
        self.clear()

    def enqueue(self, method, *args, **kwargs):
        """
        Queues a task in the pool

        :param method: Method to call
        :return: A FutureResult object, to get the result of the task
        :raise ValueError: Invalid method
        :raise Full: The task queue is full
        """
        if not hasattr(method, '__call__'):
            raise ValueError("{0} has no __call__ member."
                             .format(method.__name__))

        # Prepare the future result object
        future = FutureResult(self._logger)

        # Use a lock, as we might be "resetting" the queue
        with self.__lock:
            # Add the task to the queue
            self._queue.put((method, args, kwargs, future), True,
                            self._timeout)

            if self.__nb_active_threads == self.__nb_threads:
                # All threads are taken: start a new one
                self.__start_thread()

        return future

    def clear(self):
        """
        Empties the current queue content.
        Returns once the queue have been emptied.
        """
        with self.__lock:
            # Empty the current queue
            try:
                while True:
                    self._queue.get_nowait()
                    self._queue.task_done()
            except queue.Empty:
                # Queue is now empty
                pass

            # Wait for the tasks currently executed
            self.join()

    def join(self, timeout=None):
        """
        Waits for all the tasks to be executed

        :param timeout: Maximum time to wait (in seconds)
        :return: True if the queue has been emptied, else False
        """
        if self._queue.empty():
            # Nothing to wait for...
            return True
        elif timeout is None:
            # Use the original join
            self._queue.join()
            return True
        else:
            # Wait for the condition
            with self._queue.all_tasks_done:
                self._queue.all_tasks_done.wait(timeout)
                return not bool(self._queue.unfinished_tasks)

    def __run(self):
        """
        The main loop
        """
        with self.__lock:
            self.__nb_threads += 1

        while not self._done_event.is_set():
            try:
                # Wait for an action (blocking)
                task = self._queue.get(True, self._timeout)
                if task is self._done_event:
                    # Stop event in the queue: get out
                    self._queue.task_done()
                    with self.__lock:
                        self.__nb_threads -= 1
                        return
            except queue.Empty:
                # Nothing to do yet
                pass
            else:
                with self.__lock:
                    self.__nb_active_threads += 1

                # Extract elements
                method, args, kwargs, future = task
                try:
                    # Call the method
                    future.execute(method, args, kwargs)
                except Exception as ex:
                    self._logger.exception("Error executing %s: %s",
                                           method.__name__, ex)
                finally:
                    # Mark the action as executed
                    self._queue.task_done()

                    # Thread is not active anymore
                    self.__nb_active_threads -= 1

            # Clean up thread if necessary
            with self.__lock:
                if self.__nb_threads > self._min_threads:
                    # No more work for this thread, and we're above the
                    # minimum number of threads: stop this one
                    self.__nb_threads -= 1
                    return

        with self.__lock:
            # Thread stops
            self.__nb_threads -= 1
