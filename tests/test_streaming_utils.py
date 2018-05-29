""" tests the :module:`cc.streaming_utils` module """
import io
from math import ceil

import pytest

from jars.streaming_utils import Fragmenter, LimitedFileReader, FragmentingChunker


def test_fragmenting_chunker_fragmenting():
    """ tests the fragmenting chunker in chunk mode without fragmenting """
    golden_master = b'*' * 8

    stream = io.BytesIO(golden_master)
    result_buffer = b''

    fraggy = FragmentingChunker(stream, chunk_size=2, fragment_size=4,
                                total_size=len(golden_master))

    while not fraggy.exhausted:
        print('more')
        inner_loop_ct = 0

        # this should iterate in chunk size
        for chunk in fraggy:
            print('chunk')
            print(chunk)
            result_buffer += chunk
            inner_loop_ct += 1
        print(fraggy.exhausted)
        assert inner_loop_ct == 2

    assert golden_master == result_buffer


def test_fragmenting_chunker_chunking():
    """ tests the fragmenting chunker in chunk mode without fragmenting """

    golden_master = b'12345678'

    stream = io.BytesIO(golden_master)
    result_buffer = b''

    fraggy = FragmentingChunker(stream, chunk_size=2)

    count = 0
    for chunk in fraggy:
        result_buffer += chunk
        count += 1
    assert result_buffer == golden_master

    assert count == 4


def test_fragmenter():
    """ tests the while fragmenter functionallity """
    test_data = bytes(range(255))
    file_obj = io.BytesIO(test_data)
    existing_data = file_obj.read(10)

    fragmenter = Fragmenter(file_obj, existing_data=existing_data,
                            file_size=len(test_data),
                            fragment_size=20)
    fragmenter_iter = iter(fragmenter)
    # first segment
    first_fragment = next(fragmenter_iter)

    # slice like (inclusive) indexing
    assert first_fragment.begin == 0
    assert first_fragment.end == 19

    assert first_fragment.length == 20

    # check data
    read_data = first_fragment.file_obj.read()
    assert read_data == test_data[first_fragment.begin:first_fragment.end + 1]

    # read all the other fragments, but not the last one
    for (num, fragment) in zip(range(ceil(len(test_data) / fragmenter.fragment_size) - 2),
                               fragmenter_iter):
        # one offset from the beginning
        num = num + 1
        read_data += fragment.file_obj.read()
        assert fragment.length == 20
        assert fragment.begin == (num) * 20
        assert fragment.end == (num + 1) * 20 - 1

    # now check the last fragment
    last_segment = next(fragmenter_iter)

    read_data += last_segment.file_obj.read()
    assert read_data == test_data

    assert last_segment.length == len(test_data) % 20
    assert last_segment.begin == len(test_data) - len(test_data) % 20
    assert last_segment.end == len(test_data) - 1


def test_fragmenter_existing_data_larger_fragment():
    """ check if a ValueError is throws if the existing data is larger then the
    fragment size"""
    with pytest.raises(ValueError):
        Fragmenter(io.BytesIO(), fragment_size=10, existing_data=b'0' * 11, file_size=100)


def test_fragmenter_existing_data_larger_size():
    """ check if a ValueError is thrown if the existing data is more then the total
    file length"""
    with pytest.raises(ValueError):
        Fragmenter(io.BytesIO(), fragment_size=200, existing_data=b'0' * 101,
                   file_size=100)


def test_fragmenter_throws_unexhoused_reading():
    """ the fragmenter should raise if a fragment has not been read completle from one
    iteration to the next one """
    f_iter = iter(Fragmenter(io.BytesIO(b' ' * 100), fragment_size=20,
                             file_size=100))
    next(f_iter)

    with pytest.raises(IOError):
        next(f_iter)


def test_limited_file_reader_full_read():
    """ tests if the limited file reader only retuns its maxlength"""
    test_data = bytes(range(255))
    limited_reader = LimitedFileReader(io.BytesIO(test_data), 20)

    assert limited_reader.read() == test_data[:20]
    assert len(limited_reader.read()) == 0


def test_limited_file_reader():
    """ test of the LimitedFileReader works without prebuffer """
    test_data = bytes(range(255))
    limited_reader = LimitedFileReader(io.BytesIO(test_data), 20)

    for iteration in range(4):
        assert limited_reader.read(5) == bytes(range(iteration * 5, (iteration + 1) * 5))
    assert len(limited_reader.read(5)) == 0


def test_limited_file_reader_prebuffer():
    """ tests if the LimitedFileReader returns the prebuffer correctly with read calls """
    test_data = bytes(range(255))
    f_obj = io.BytesIO(test_data)
    prebuffer = f_obj.read(10)
    limited_reader = LimitedFileReader(f_obj, 20, prebuffer)

    for iteration in range(4):
        assert limited_reader.read(5) == bytes(range(iteration * 5, (iteration + 1) * 5))

    assert len(limited_reader.read(5)) == 0
