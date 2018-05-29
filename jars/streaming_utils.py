"""
This module contains utilities to work with file objects.
"""
from collections import namedtuple
from math import ceil


class FragmentingChunker:
    """ generator to upload the file in chunks and additionaly in fragments if needed
    Some uploads require that a stream is splitted into fragments, which are portions of
    uploads. This class should enable to upload this fragments.
    :ivar first_chunk: sometimes one need to inspect the first bytes outside of this class
    if you do so you can put that value back into the chunker here
    :ivar file_obj: the object which is wrapped
    :ivar chunk_size: the __iter__ returns an iterator which iterates over
    fragment_size/chunk_size parts if fragment size is given
    :ivar total_read: count of read bytes
    :ivar total_size: if fragment_end is used fragment_size is needed to calcuate it
    """

    def __init__(self, file_obj, chunk_size=1024 * 16, first_chunk=None, fragment_size=0,
                 total_size=0):
        # pylint: disable=too-many-arguments
        if fragment_size % chunk_size != 0:
            raise ValueError("chunk_size must be multiple of fragment_size")
        self.first_chunk = first_chunk
        self.file_obj = file_obj
        self.chunk_size = chunk_size
        self.total_read = 0
        self.fragment_size = fragment_size
        self._exhausted = False
        self.total_size = total_size

    @property
    def fragment_begin(self):
        """ returns the bytesoffset """
        return self.total_read

    @property
    def fragment_end(self):
        """ returns the bytesoffset of the end of the fragment -1 """
        if (self.total_read + self.fragment_size) > self.total_size:
            return self.total_size - 1
        else:
            return self.total_read + self.fragment_size - 1

    @property
    def exhausted(self):
        """ returns True if there is nothing left to read """
        return self._exhausted or self.total_read == self.total_size

    def __iter__(self):
        fragment_read = 0
        if self.first_chunk:
            # return first chunk and set it to zero
            self.total_read += len(self.first_chunk)
            fragment_read += len(self.first_chunk)
            yield self.first_chunk
            self.first_chunk = None
        while True:
            buf = self.file_obj.read(self.chunk_size)
            self.total_read += len(buf)
            fragment_read += len(buf)
            if not buf:
                self._exhausted = True
                break
            yield buf
            if self.fragment_size and fragment_read >= self.fragment_size:
                break


class LimitedFileReader(object):
    """
    This wraps a `file object <https://docs.python.org/3/glossary.html#term-file-object>`_
    , to act like a smaller file.
    """

    def __init__(self, file_obj, limit=1024 * 1024 * 1024 * 1024 * 1024, pre_buffer=b''):
        """
        :param file_obj: the file like object with a read method to be wrapped
        :param limit: this is the size, which the file like object is limited to
        :param pre_buffer: if there is already data read from the stream, this can be
        passed in here and will be
        prepended to the read calls
        """
        self.file_object = file_obj
        self.limit = limit
        self.read_num = 0
        self._pre_buffer = pre_buffer

    def read(self, length=None):
        """ like the read method of a file like object

        :param length: reads until file is exhausted or the limit is reached
        :returns a :class:`bytes` objects containing the read stuff
        """
        if not length:
            length = self.limit

        to_read = min(self.limit - self.read_num, length)

        # joining buffer is faster then adding them
        buf = []
        if len(self._pre_buffer):
            # if there is a prebuffer fetch as much as needed and assign the rest to the
            # _pre_buffer member
            buf.append(self._pre_buffer[:to_read])
            self._pre_buffer = self._pre_buffer[to_read:]
            to_read -= len(buf[0])

        buf.append(self.file_object.read(to_read))

        result_buffer = b''.join(buf)
        self.read_num += len(result_buffer)
        return result_buffer


Fragment = namedtuple('Fragment', ['begin', 'end', 'file_obj', 'length'])
""" A Fragment returned by the Fragmenter

:var begin: Index of the beginning
:var end: Index of the end
:var file_obj: The file object for the length of the fragment
:var length: The length of this particular fragment
"""


class Fragmenter(object):
    """
    This is a helper particularly for uploads, which are split into several parts, called
    fragments. The class is then used as iterator, which then returns :class:`Fragment`
    instances.
    """

    def __init__(self, file_obj, file_size, fragment_size, existing_data=b''):
        """
        :param file_obj: The `file object
        <https://docs.python.org/3/glossary.html#term-file-object>` to be fragmented
        :param file_size: The total size of the file, including pre-fetched data
        :param fragment_size: The size of one fragment
        :param existing_data: If any data was pre-fetched pass from `file_obj` it in here.
        """
        if len(existing_data) > file_size:
            raise ValueError('file size can\'t be smaller then existing_data')

        if len(existing_data) > fragment_size:
            raise ValueError(
                'its not allowed to have a larger existing data then fragment size')

        self.file_obj = file_obj
        self.existing_data = existing_data
        self.file_size = file_size
        self.fragment_size = fragment_size

    def __iter__(self):
        data_read = 0
        for part in range(ceil(self.file_size / self.fragment_size)):
            begin = part * self.fragment_size

            fragment_size = min(self.fragment_size,
                                self.file_size - part * self.fragment_size)
            file_obj = LimitedFileReader(self.file_obj, limit=self.fragment_size,
                                         pre_buffer=self.existing_data)

            # after passing the existing data to the LimitedFileReader, it is not needed
            # anymore in here(its not allowed to have more existing data then the fragment
            #  size)
            self.existing_data = b''

            fragment = Fragment(begin, begin + fragment_size - 1, file_obj, fragment_size)
            yield fragment
            data_read += fragment.file_obj.read_num
            if data_read != fragment.end + 1:
                raise IOError('Last file_obj was not read completely')
