#! /usr/bin/env python3
#
# author: Eugene Ivanyuk (eugenyuk@gmail.com)
#
# Useful bzip2 spec (thanks to Joe Tsai):
# https://github.com/dsnet/compress/blob/master/doc/bzip2-format.pdf

import sys
from bitstring import ConstBitStream
import argparse
import datetime
from profilehooks import timecall, profile

BLOCK_START_PATTERN = 0x314159265359
MAX_HUFF_CODE_BITS = 20
HUFF_TREE_SIZE = 50
HUFF_SYMBOLS_MAX = 258
RUN_A = 0
RUN_B = 1
FIRST_BLOCK_POS = 32
SUPPORTED_DATETIME_FORMATS = [  "%Y-%m-%dT%H:%M:%S",	# "2017-02-21T14:53:22"
                                "%b %d %H:%M:%S",	    # "Oct 30 05:54:01" 
                                "%Y-%m-%d %H:%M:%S",	# "2017-02-21 14:53:22"
                                "%d/%b/%Y:%H:%M:%S"     # "12/Dec/2015:18:39:27"
                             ]

class Error (Exception): pass
class StreamHeaderMagicError (Error): pass
class StreamHeaderVersionError (Error): pass
class StreamHeaderLevelError (Error): pass
class BlockHeaderMagicError (Error): pass
class BlockHeaderRandomizedError (Error): pass
class BlockHeaderOrigPtrError (Error): pass

# bzip2 file headers value
bz2Data = {}


def process_options():
    parser = argparse.ArgumentParser()
    parser.add_argument(    '--from',
                            dest = 'start',
                            required = True,
                            help = 'Start datetime string.',
                            type = validate_datetime_string )
    parser.add_argument(    '--to',
                            dest = 'end',
                            required = True,
                            help = 'End datetime string.',
                            type = validate_datetime_string )
    parser.add_argument(    '--file',
                            required = True,
                            help = 'Set input bz2 file.',
                            type = argparse.FileType('r') )
    parsedOpts = parser.parse_args()

    optFrom, optFromFormat = parsedOpts.start
    optTo, optToFormat = parsedOpts.end
    #print("parsedOpts.start datetime string = " + str(optFrom))
    #rint("parsedOpts.start datetime format = " + str(optFromFormat))
    #print("parsedOpts.end datetime string = " + str(optTo))
    #print("parsedOpts.end datetime format = " + str(optToFormat))

    if optFromFormat != optToFormat:
        msg = "Datetime formats of --from {} and --to {} are not equal."
        raise ValueError(msg.format(optFromFormat, optToFormat))

    return optFrom, optTo, parsedOpts.file


def validate_datetime_string(datetimeStr):
    # validate --from, --to datetime strings
    for i, datetimeFormat in enumerate(SUPPORTED_DATETIME_FORMATS):
        try:
            return  datetime.datetime.strptime(datetimeStr, datetimeFormat), \
                    datetimeFormat
        except ValueError:
            if i == len(SUPPORTED_DATETIME_FORMATS) - 1:
                msg = "Not a valid date: '{0}'.".format(datetimeStr)
                raise argparse.ArgumentTypeError(msg)
            else:
                continue


def parse_stream_header(bitStream):
    # read StreamHeader:= HeaderMagic Version Level
    hStreamMagic = bitStream.read(16).bytes
    hStreamVersion = bitStream.read(8).bytes
    hStreamLevel = bitStream.read(8).bytes

    # Check if bz2 file starts with BZh['1'-'9'] (1-9 are ascii chars)
    try:
        if hStreamMagic != b'BZ':
            raise StreamHeaderMagicError
        if hStreamVersion != b'h':
            raise StreamHeaderVersionError
        if hStreamLevel < b'1' or hStreamLevel > b'9':
            raise StreamHeaderLevelError
    except StreamHeaderMagicError:
        print("ERROR: This is not bz2 file. Header Magic (2 bytes) is not 'BZ'.")
        exit(1)
    except StreamHeaderVersionError:
        print("ERROR: Stream header Version is not 'h'.")
        exit(1)
    except StreamHeaderLevelError:
        print("ERROR: Stream header Level is not '1'-'9'.")
        exit(1)
    
    # Store streamHeaderLevel into global dictionary bz2Data
    bz2Data['StreamHeaderLevel'] = hStreamLevel


def parse_stream_block(bitStream):
    parse_block_header(bitStream)
    blockTrees = parse_block_trees(bitStream)

    return blockTrees


def parse_block_header(bitStream):
    # read BlockHeader:= BlockMagic BlockCRC Randomized OrigPtr
    hBlockMagic = bitStream.read(48).int
    hBlockCRC = bitStream.read(32).bytes
    hBlockRandomized = bitStream.read(1)
    hBlockOrigPtr = bitStream.read(24).int

    # convert StreamHeaderLevel from bytes to int and calc size of block 
    blockSize = (bz2Data['StreamHeaderLevel'][0] - b'0'[0]) * 100000
    bz2Data['blockSize'] = blockSize

    try:
        if hBlockMagic != BLOCK_START_PATTERN:
            raise BlockHeaderMagicError
        if hBlockRandomized:
            raise BlockHeaderRandomizedError
        if hBlockOrigPtr > blockSize:
            raise BlockHeaderOrigPtrError
    except BlockHeaderMagicError:
        print("ERROR: Block header Magic " + str(hex(hBlockMagic)) +
              " isn't equal to block start magic number " 
              + str(hex(BLOCK_START_PATTERN)))
        exit(1)
    except BlockHeaderRandomizedError:
        print("ERROR: Block header Randomized is 1 which is deprecated.")
        exit(1)
    except BlockHeaderOrigPtrError:
        print("ERROR: Block header OrigPtr is " + str(hBlockOrigPtr)
            + ", which is more than block size " + str(blockSize))
        exit(1)
    
    bz2Data['BlockHeaderCRC'] = hBlockCRC
    bz2Data['BlockHeaderOrigPtr'] = hBlockOrigPtr


def parse_block_trees(bitStream):
    symbolStack = parse_sym_map(bitStream)
    #print("symbolStack = " + str(symbolStack))
    #print("symbolStack length = " + str(len(symbolStack)))
    numTrees = parse_num_trees(bitStream)
    #print("numTrees = " + str(numTrees))
    numSelectors = parse_num_selectors(bitStream)
    #print("numSelectors = " + str(numSelectors))
    selectors = parse_selectors(bitStream, numTrees, numSelectors)
    #print("Selectors = " + str(Selectors))
    trees = parse_trees(bitStream, numTrees, symbolStack)
    #print("trees = " + str(trees))

    blockTrees = {'symbolStack': symbolStack,
                  'numTrees': numTrees,
                  'numSelectors': numSelectors,
                  'selectors': selectors,
                  'trees': trees}

    return blockTrees


def parse_sym_map(bitStream):
    """ The SymMap represents the symbol stack used in the MTF stage by using
    a two-level bit-map to indicate which symbols are present. The first element
    MapL1, is a 16-bit integer where each bit corresponds to a contiguous
    16-symbol region of the full 256-symbol space. The leading bit corresponds
    with symbols, the next bit with symbols 16..31, and so on. The number of
    bits set determines the number of MapL2 elements to follow, which are also
    16-bit integers. Similar to the first level, the leading bits correspond
    to the lower symbols in the associated 16-symbol region. If the bit is set,
    then that indicates that the corresponding symbol is present. """
    # sorted stack of used symbols
    symbolStack = []
    mapL1 = bitStream.read(16).uint

    for i in range(16):
        if mapL1 & (0x8000 >> i):
            mapL2 = bitStream.read(16).uint
            for j in range(16):
                if mapL2 & (0x8000 >> j):
                    symbolStack.append(16 * i + j)

    return symbolStack


def parse_num_trees(bitStream):
    """ The numTrees field is a 3-bit integer indicating the number of Huffman
    trees used in the HUFF stage. It must be between 2..6. The number may be
    larger than necessary; that is, it is permissible to define a Huffman tree
    that does not end up being used to decode any symbol in BlockData. """
    numTrees = bitStream.read(3).uint
    if numTrees < 2 or numTrees > 6:
        print("ERROR: numTrees is " + str(numTrees) + ". Must be in 2..6 range.")
        exit(1)
    # good example of how to handle exceptions
    #try:
    #    numTrees <= 2 and numTrees <= 6 
    #except Exception as ex:
    #    template = "An exception of type {0} occurred. Arguments:\n{1!r}"
    #    message = template.format(type(ex).__name__, ex.args)
    #    print(message)
    
    return numTrees


def parse_num_selectors(bitStream):
    """ Parse a number of selectors from file's header.

    The numSelectors field is a 15-bit integer indicating the number of selectors
    used in the Huffman conding stage. """
    numSelectors = bitStream.read(15).uint
    if not numSelectors:
        print("ERROR: NumSelectors is " + str(numSelectors) + 
              ". Must be in 1..65535 range.")
        exit(1)
    
    return numSelectors


def parse_selectors(bitStream, numTrees, numSelectors):
    """ Parse selectors list from file's header. 
    
    Represents the selectors list used in the Huffman conding stage. To
    encode the selectors, a move-to-front transform is first applied and then
    each index in the resulting list is written out as a zero-terminated
    sequence of one-bits. 
        The selectors list simply contains the index of which Huffman tree to
    use. For example, if there were 243 symbols to encode (including the EOB
    symbol), then we know that we would need 5 selectors. One possible selectors
    list could be: [0, 0, 1, 2, 1]. In this situation, we would use tree 0 for
    the first 100 symbols, tree 1 for the next 50 symbols, tree 2 for the next
    50 symbols, and tree 1 for the last 43 symbols. For this given selector
    list, there must be at least 3 Huffman trees. 
        Function returns a list of integers, where each integer is the index
    of the Huffman tree used to decode the corresponding group of Huffman codes.
    """
    idxs = []
    # NEED CHANGE _ with i enumerate
    for _ in range(numSelectors):
        i = 0
        while bitStream.read(1):
            i += 1
            assert(i < numTrees)
        idxs.append(i)
    #print("idxs = " + str(idxs))

    # Current list of indexes is encoded with MTF, so decode it.
    selectors = decode_mtf(idxs, list(range(numTrees)))

    return selectors

#@timecall
def decode_mtf(idxs, stack):
    """ The idea behind MTF encoding: 
    INPUT: 
    * stream of symbols
    * sorted stack of all the unique symbols that appear in syms
    1. Take the first symbol from a stream
    2. Save an index of that symbol in a stack
    3. Move that symbol to front of a stack with index 0
    4. Add symbol's index to a list of indexes
    RETURN: list of indexes

        The idea behind MTF decoding:
    INPUT:
    * list of indexes
    * sorted stack of all the unique symbols that appear in syms
    1. Take the first index from a list of indexes
    2. Take a symbol with that index from a stack
    3. Move that symbol to front of a stack with index 0
    4. Add a symbol to a list of symbols
    RETURN: list of symbols
    """
    decodedSymbols = []
    for i in idxs:
        s = stack[i]
        stack = [stack.pop(i)] + stack
        decodedSymbols.append(s)

    return decodedSymbols


def parse_trees(bitStream, numTrees, symbolStack):
    trees = []
    NumSyms = len(symbolStack) + 2
    for _ in range(numTrees):
        clens = []
        clen = bitStream.read(5).int
        for _ in range(NumSyms):
            while True:
                assert(clen > 0 and clen <= MAX_HUFF_CODE_BITS)
                if not bitStream.read(1):
                    break
                clen -= +1 if bitStream.read(1) else -1
            clens.append(clen)
        trees.append(clens)
    
    return trees


def init_crc32_table():
    """ Initialize CRC32 table.

    Understanding CRC32:
    https://github.com/Michaelangel007/crc32
    http://www.sunshine2k.de/articles/coding/crc/understanding_crc.html """
    # generator polynomial
    POLY = 0x04c11db7
    crc32Table = []

    for i in range(256):
        crc = i << 24
        for _ in range(8):
            crc = (crc << 1) ^ POLY if (crc & 0x80000000) else (crc << 1)
        crc32Table.append(crc & 0xffffffff)
    
    return crc32Table


def decompress_block(blockTrees, bitStream):
    rle2Symbols = decode_huffman_codes(blockTrees, bitStream)
    #print("huffSymbols = " + str(huffSymbols))
    mtfSymbols = decode_rle2(rle2Symbols)
    #print("rle2Symbols = " + str(rle2Symbols))
    bwtSymbols = decode_mtf(mtfSymbols, blockTrees['symbolStack'])
    #print("mtfSymbols = " + str(mtfSymbols))
    rle1Symbols = decode_bwt(bwtSymbols)
    #print(rle1Symbols.decode())
    decompressedSymbols = decode_rle1(rle1Symbols.decode())

    # check decompressed block CRC
    blockCRC = calc_block_crc32(decompressedSymbols)

    headerCRC = int.from_bytes( bz2Data['BlockHeaderCRC'],
                                byteorder='big',
                                signed=True )

    # check if calculated crc of block data equals to header crc value
    if blockCRC != headerCRC:
        msg = "block CRC {} != header CRC {}."
        raise ValueError(msg.format(blockCRC, headerCRC))

    return decompressedSymbols

#@timecall
#@profile
def decode_huffman_codes(blockTrees, bitStream):
    """ Decode bits into Huffman coded symbols.
    
    1-st stage of bzip2 decompression stack.
    Decode bits of the block data by using the Huffman tables and selectors
    list obtained from block header in parse_selectors()l.
    """
    decodedSymbols = []
    symbolsCounter = 0
    #print(blockTrees['numTrees'])
    selectors = iter(blockTrees['selectors'])
    # symbolStack is the number of symbols in the stack from MTF stage.
    # Subtract 1 for losing the 0 symbol in the RLE2 stage and add 3 for
    # gaining RUNA, RUNB, EOB symbols
    huffSymbolStack = len(blockTrees['symbolStack']) - 1 + 3
    EOB = huffSymbolStack - 1
    #print("EOB = " + str(EOB))

    trees = blockTrees['trees']
    huffTreesData = create_decode_huffman_tables(trees)
    #print("tree\tminLen\tmaxLen\tcurlen\tsymbol\tpermutes")

    #print("selectors = " + str(blockTrees['selectors']))
    huffSymbol = 0
    while huffSymbol < EOB:
        if symbolsCounter == 0:
            symbolsCounter = HUFF_TREE_SIZE
            curSelector = next(selectors)
            #print("curSelector = " + str(curSelector))
            permutes = huffTreesData[curSelector]['permutes']
            #print("permutes = " + str(permutes))
            limits = huffTreesData[curSelector]['limits']
            #print("limits = " + str(limits))
            bases = huffTreesData[curSelector]['bases']
            #print("bases = " + str(bases))
            minLen = huffTreesData[curSelector]['minLen']
            #print("minLen = " + str(minLen))
            maxLen = huffTreesData[curSelector]['maxLen']
            #print("maxLen = " + str(maxLen))
        #print("{}".format(curSelector), end="\t")


        huffSymbol, huffSymbolLen = \
            read_huffman_coded_symbol(minLen, maxLen, bitStream, limits)

        symbolsCounter -= 1

        # decode Huffman coded symbol (with bounds checking)
        huffSymbol = (huffSymbol >> (maxLen - huffSymbolLen)) - bases[huffSymbolLen]

        if huffSymbol >= HUFF_SYMBOLS_MAX:
            msg = "huffSymbol {} can't be >= {}."
            raise ValueError(msg.format(huffSymbol, HUFF_SYMBOLS_MAX))

        huffSymbol = permutes[huffSymbol]
        decodedSymbols.append(huffSymbol)
        #print(huffSymbol)

    return decodedSymbols

#@timecall
def read_huffman_coded_symbol(minLen, maxLen, bitStream, limits):
    """Read Huffman coded symbol. """
    """
    huffSymbolLen = minLen
    huffSymbol = bitStream.read('uint:{}'.format(huffSymbolLen))
    while True:
        if huffSymbolLen > maxLen:
            raise ValueError("huffSymbolLen can't be > maxLen")
        if huffSymbol <= limits[huffSymbolLen]:
            break
        huffSymbolLen += 1
        # read additional bit
        huffSymbol = (huffSymbol << 1) | bitStream.read('uint:1')
    """
    #"""
    huffSymbol = bitStream.read('uint:{}'.format(maxLen))
    
    huffSymbolLen = minLen
    while huffSymbol > limits[huffSymbolLen]:
        huffSymbolLen += 1
    if huffSymbolLen > maxLen:
        msg = "huffman symbol length {} can't be > maxLen. Bad bzip2 data."
        raise ValueError(msg.format(huffSymbolLen, maxLen))
    
    #print("bitStream.pos before correction = " + str(bitStream.pos))
    bitStream.pos -= maxLen - huffSymbolLen
    #print("bitStream.pos after correction = " + str(bitStream.pos))
    #print("huffSymbol = {}, huffSymbolLen = {}".format(huffSymbol, huffSymbolLen))
    #exit(1)
    #"""

    #print("bitStream.pos = " + str(bitStream.pos))
    return huffSymbol, huffSymbolLen

#timecall
def create_decode_huffman_tables(trees):
    """ Generate several tables which are used to decode huffman codes. """
    huffTreesData = {}
    for i, tree in enumerate(trees):
        minLen = min(tree)
        maxLen = max(tree)

        permutes = generate_permutes_table(minLen, maxLen, tree)
        #print("permutes = " + str(permutes))

        limits = generate_limits_table(minLen, maxLen, tree)
        #print("limits = " + str(limits))
                
        bases = generate_bases_table(minLen, maxLen, tree, limits)
        #print("bases = " + str(bases))

        huffTreesData.update({i:{'permutes': permutes,
                                 'limits': limits,
                                 'bases': bases,
                                 'minLen': minLen,
                                 'maxLen': maxLen }
                            })
    #exit(1)
    return huffTreesData

#@timecall
def generate_permutes_table(minLen, maxLen, Tree):
    """Generate permutes table.
    
    This is the lookup table for converting huffman coded symbols into decoded
    symbols. bases table is the amount to subtract from the value of a huffman
    symbol of a given length when using permutes.
    """
    permutes = []
    for length in range(minLen, maxLen + 1):
        for itemIdx, treeItem in enumerate(Tree):
            if treeItem == length:
                permutes.append(itemIdx)

    return permutes

#@timecall
def generate_limits_table(minLen, maxLen, Tree):
    """Generates limits table.
    
    Which stores the largest symbol-coding value at each bit length, which is
    (previous limit << 1) + symbols at this level.
    """
    limits = [0] * (maxLen + 1)
    symLenCount = symbols_length_count(maxLen, Tree)
    vec = 0
    for length in range(minLen, maxLen + 1):
        vec += symLenCount[length]
        limits[length] = (vec << (maxLen - length)) - 1
        vec <<= 1

    return limits

#@timecall
def generate_bases_table(minLen, maxLen, Tree, limits):
    """Generate bases table.
    
    It stores number of symbols to ignore at each bit length, which is:
    limit - cumulative count of symbols coded for already.
    """
    bases = [0] * (maxLen + 1)
    symLenCount = symbols_length_count(maxLen, Tree)
    t, pp = 0, 0
    for length in range(minLen, maxLen):
        #startVal = ((limits[length] + 1) << 1)
        pp += symLenCount[length]
        t += symLenCount[length]
        pp <<= 1
        #bases[length + 1] = startVal - t
        bases[length + 1] = pp - t

    return bases


def symbols_length_count(maxLen, Tree):
    """Create a list of symbol bit lengths (kind of a histogram).
    
    Where list's index is symbol's bit length and list's element is the count
    of such symbols.
    """
    symLenCount = [0] * (maxLen + 1)
    for treeItem in Tree:
        symLenCount[treeItem] += 1

    return symLenCount

#@timecall
def decode_rle2(rle2Symbols):
    """Decode RLE2 symbols.
    
    2-nd stage of bzip2 decompression stack.
    Decode RLE2 symbols by converting RUN_A and RUN_B sybmols (0 and 1) to run
    of zeroes.
    Decrement every symbol except RUN_A, RUN_B, EOB. So the resulting list of
    indexes is ready fom MTF decoding.
    """

    decodedSymbols = []
    blockSize = bz2Data['blockSize']
    runPos, zeroCounter = 0, 0
    
    for rle2Symbol in rle2Symbols:
        #print(rle2Symbol)
        if rle2Symbol <= RUN_B:
            # If this is the start of a new run, zero out counter
            if runPos == 0:
                runPos = 1
                zeroCounter = 0
            # Neat trick that saves 1 symbol: instead of or-ing 0 or 1 at
			# each bit position, add 1 or 2 instead.  For example,
			# 1011 is 1<<0 + 1<<1 + 2<<2.  1010 is 2<<0 + 2<<1 + 1<<2.
			# You can make any bit pattern that way using 1 less symbol than
			# the basic or 0/1 method (except all bits 0, which would use no
			# symbols, but a run of length 0 doesn't mean anything in this
			# context). Thus space is saved.
            zeroCounter += (runPos << rle2Symbol)            
            runPos <<= 1
            #print("zeroCounter = " + str(zeroCounter))
            continue

        # When we hit the first non-run symbol after a run, we now know
		# how many times to repeat the last literal, so append that many
		# copies to our buffer of decoded symbols (dbuf) now.  (The last
		# literal used is the one at the head of the mtfSymbol array.) */
        if runPos:
            runPos = 0
            
            if len(rle2Symbols) + zeroCounter >= blockSize:
                msg = "Amount of RLE2 symbols {} + amount of zeros {} can't be \
                >= size of block {}."
                raise ValueError(msg.format(len(rle2Symbols), zeroCounter, 
                                blockSize))
            
            decodedSymbols.extend([0] * zeroCounter)

        # decrement every non RUNA, RUNB, EOB symbols to conform to mtf alphabet
        decodedSymbols.append(rle2Symbol - 1)


    # delete EOB symbol
    del decodedSymbols[-1]

    return decodedSymbols

#@timecall
def decode_bwt(bwtSymbols):
    """Decode BWT symbols.

    """
    origPtr = bz2Data['BlockHeaderOrigPtr']
    #print("origPtr = " + str(origPtr))
    charsCount = chars_count(bwtSymbols)
    #print(charsCount)

    charsStartPos = chars_start_pos(charsCount)
    #print(charsStartPos)

    permBWT = permute_bwt(bwtSymbols, charsStartPos)
    #print(permBWT)

    if origPtr >= len(permBWT):
        msg = "origPtr {} can't be >= amout of decompressed characters {}."
        raise ValueError(msg.format(origPtr, len(permBWT)))

    i = permBWT[origPtr]
    #print("permBWT[origPtr] = " + str(i))
    decodedSymbols = bytearray(len(bwtSymbols))
    for j in range(len(bwtSymbols)):
        decodedSymbols[j] = bwtSymbols[i]
        i = permBWT[i]
    
    return decodedSymbols


def chars_count(bwtSymbols):
    """ Count amount of every character.
    
    charsCount index - character value
    charsCount value - amount of characters of given value
    """
    charsCount = [0] * 256
    for bwtSymbol in bwtSymbols:
        charsCount[bwtSymbol] += 1
    
    return charsCount


def chars_start_pos(charsCount):
    """ Find every char start position of BWT data.

    charsCount gives us amount of every char occurence. Given this we calculate
    start position of every character in encoded BWT data if it would be sorted.
    """
    charsStartPos, n = [0] * 256, 0
    for i, v in enumerate(charsCount):
        charsStartPos[i] = n
        n += v
    
    return charsStartPos


def permute_bwt(bwtSymbols, charsStartPos):
    perm = [0] * len(bwtSymbols)
    for i, v in enumerate(bwtSymbols):
        perm[charsStartPos[v]] = i
        #print("bwt = {}, charsStartPos[v] = {}, perm[charsStartPos[v]] = {}".format(v,
        #    charsStartPos[v], perm[charsStartPos[v]]))
        charsStartPos[v] += 1
        
    return perm

#@timecall
def decode_rle1(rle1Symbols):
    """Decode RLE1 symbols.

    """
    decodedSymbols = ""
    runLenByte = 0
    runCounter = 5
    prevSym = ''

    for curSym in rle1Symbols:
        runCounter -= 1
        
        if runCounter == 0:
            runLenByte = ord(curSym)
            runCounter = 5
            decodedSymbols += (prevSym * runLenByte)
            #print("curSym = {} runLenByte = {} {}".format(curSym, runLenByte,
            #  prevSym * runLenByte))
            continue
        
        if curSym != prevSym:
            runCounter = 4
            prevSym = curSym

        decodedSymbols += curSym

    return decodedSymbols

#@timecall
def calc_block_crc32(decompressedBlock):
    crc = 0xffffffff

    crc32Table = init_crc32_table()
    #for i, v in enumerate(crc32Table):
    #    if (i + 1) % 8 == 0:
    #        print(hex(v))
    #    else:
    #        print(hex(v), end=' ')

    for curSym in decompressedBlock:
        crc = ((crc << 8) & 0xffffffff) ^ crc32Table[(crc >> 24) ^ ord(curSym)]
        #print("crc = " + str(crc))
    
    return ~crc


def main():
    optFrom, optTo, optFile = process_options()

    bitStream = ConstBitStream(optFile)
    #blockNumbers = bitStream.findall(BLOCK_START_PATTERN)
    #print(sum(1 for x in blockNumbers))

    parse_stream_header(bitStream)
    blockTrees = parse_stream_block(bitStream)
    
    decompressedBlock = decompress_block(blockTrees, bitStream)
    #print(decompressedBlock)

    return 0


if __name__ == '__main__':
    sys.exit(main())