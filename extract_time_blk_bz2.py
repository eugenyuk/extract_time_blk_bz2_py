#! /usr/bin/env python3
#
# author: Eugene Ivanyuk (eugenyuk@gmail.com)
#
# Useful bzip2 spec (thanks to Joe Tsai):
# https://github.com/dsnet/compress/blob/master/doc/bzip2-format.pdf

import sys
import bitstring
import argparse
from datetime import datetime
from profilehooks import timecall, profile


BLOCK_START_PATTERN = '0x314159265359'
STREAM_END_PATTERN = '0x177245385090'
MAX_HUFF_CODE_BITS = 20
HUFF_TREE_SIZE = 50
HUFF_SYMBOLS_MAX = 258
RUN_A = 0
RUN_B = 1
FIRST_BLOCK_POS = 32
SUPPORTED_DATETIME_FORMATS = [ "%Y-%m-%dT%H:%M:%S",	# "2017-02-21T14:53:22"
                               "%b %d %H:%M:%S",	    # "Oct 30 05:54:01" 
                               "%Y-%m-%d %H:%M:%S",	# "2017-02-21 14:53:22"
                               "%d/%b/%Y:%H:%M:%S"   # "12/Dec/2015:18:39:27"
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


class Bz2Block():
    
    def __init__(self, bitStream):
        self.blockHeader = self.parse_block_header(bitStream)
        self.blockBitStream = self.copy_block_bitstream_to_buffer(bitStream)
        #self.blockBitStream = bitStream
        self.blockTrees = self.parse_block_trees()

    def copy_block_bitstream_to_buffer(self, bitStream):
        """Copy block bitstream to memory buffer"""
        try:
            return bitStream.readto(BLOCK_START_PATTERN)
        except bitstring.ReadError:
            return bitStream.readto(STREAM_END_PATTERN)
    
    def parse_block_header(self, bitStream):
        """Parse block headers: BlockMagic, BlockCRC, Randomized, OrigPtr."""
        hMagic, hCRC, hRandomized, hOrigPtr = \
            bitStream.readlist('uint:48, uint:32, uint:1, uint:24')
        
        blockHeader = { 'hMagic':       hMagic,
                        'hCRC':         hCRC,
                        'hRandomized':  hRandomized,
                        'hOrigPtr':     hOrigPtr
                      }

        self.validate_block_header(blockHeader)

        return blockHeader

    def validate_block_header(self, blockHeader):
        if blockHeader['hMagic'] != int(BLOCK_START_PATTERN, 16):
            msg = ("Block header Magic {} isn't equal to block start magic "
                "number {}")
            raise BlockHeaderMagicError(msg.format(blockHeader['hMagic'], 
                BLOCK_START_PATTERN))
        if blockHeader['hRandomized']:
            msg = "Block header Randomized is 1 which is deprecated."
            raise BlockHeaderRandomizedError()
        if blockHeader['hOrigPtr'] > bwtBufferLimit:
            msg = ("Block header OrigPtr is {}, which is more than max size "
                "of decompressed block {}.")
            raise BlockHeaderOrigPtrError(msg.format(blockHeader['hOrigPtr'],
                bwtBufferLimit))

    def parse_block_trees(self):
        symbolStack = self.parse_sym_map()
        #print("symbolStack = " + str(symbolStack))
        #print("symbolStack length = " + str(len(symbolStack)))
        numTrees = self.parse_num_trees()
        #print("numTrees = " + str(numTrees))
        numSelectors = self.parse_num_selectors()
        #print("numSelectors = " + str(numSelectors))
        selectors = self.parse_selectors(numTrees,
            numSelectors)
        #print("Selectors = " + str(selectors))
        #exit(1)
        trees = self.parse_trees(numTrees, symbolStack)
        #print("trees = " + str(trees))

        blockTrees = {'symbolStack':    symbolStack,
                      'numTrees':       numTrees,
                      'numSelectors':   numSelectors,
                      'selectors':      selectors,
                      'trees':          trees}

        return blockTrees

    def parse_sym_map(self):
        """Parse symbols which are presented in decompressed data

        The SymMap represents the symbol stack used in the MTF stage by
        using a two-level bit-map to indicate which symbols are present. The
        first element MapL1, is a 16-bit integer where each bit corresponds
        to a contiguous 16-symbol region of the full 256-symbol space. The
        leading bit corresponds with symbols, the next bit with symbols 16..31,
        and so on. The number of bits set determines the number of MapL2
        elements to follow, which are also 16-bit integers. Similar to the
        first level, the leading bits correspond to the lower symbols in the
        associated 16-symbol region. If the bit is set, then that indicates
        that the corresponding symbol is present.
        """
        # sorted stack of used symbols
        symbolStack = []
        mapL1 = self.blockBitStream.read('uint:16')

        for i in range(16):
            if mapL1 & (0x8000 >> i):
                mapL2 = self.blockBitStream.read('uint:16')
                for j in range(16):
                    if mapL2 & (0x8000 >> j):
                        symbolStack.append(16 * i + j)

        return symbolStack
    
    def parse_num_trees(self):
        """Parse a number of huffman trees used in a block.

        The numTrees field is a 3-bit integer indicating the number of
        Huffman trees used in the HUFF stage. It must be between 2..6. The
        number may be larger than necessary; that is, it is permissible to
        define a Huffman tree that does not end up being used to decode any
        symbol in BlockData.
        """
        numTrees = self.blockBitStream.read('uint:3')

        if numTrees not in range(2, 6+1):
            msg = "Number of huffman trees is {}. Must be in range 2..6."
            raise ValueError(msg.format(numTrees))
        # good example of how to handle exceptions
        #try:
        #    numTrees <= 2 and numTrees <= 6 
        #except Exception as ex:
        #    template = "An exception of type {0} occurred. Arguments:\n{1!r}"
        #    message = template.format(type(ex).__name__, ex.args)
        #    print(message)

        return numTrees
    
    def parse_num_selectors(self):
        """Parse a number of selectors from file's header.

        The numSelectors field is a 15-bit integer indicating the number of
        selectors used in the Huffman conding stage.
        """
        numSelectors = self.blockBitStream.read('uint:15')

        if not numSelectors:
            msg = "Number of selectors is {}. Must be in 1..65535 range.."
            raise ValueError(msg.format(numSelectors))

        return numSelectors
    #@profile
    def parse_selectors(self, numTrees, numSelectors):
        """Parse selectors list from block header. 

        Represents the selectors list used in the Huffman conding stage. To
        encode the selectors, a move-to-front transform is first applied and
        then each index in the resulting list is written out as a 
        zero-terminated sequence of one-bits. 
            The selectors list simply contains the index of which Huffman tree
        to use. For example, if there were 243 symbols to encode (including
        the EOB symbol), then we know that we would need 5 selectors. One
        possible selectors list could be: [0, 0, 1, 2, 1]. In this situation,
        we would use tree 0 for the first 100 symbols, tree 1 for the next 50
        symbols, tree 2 for the next 50 symbols, and tree 1 for the last 43
        symbols. For this given selector list, there must be at least 3
        Huffman trees. Function returns a list of integers, where each integer
        is the index of the Huffman tree used to decode the corresponding
        group of Huffman codes.
        """

        # Preserve bitStream.pos
        bitStreamPreservedPos = self.blockBitStream.pos

        # Read max possible selectors bits into memory
        selectorsBuffer = self.blockBitStream.read(numSelectors * 6)
        #print("maxSelBitstream = " + str(selectorsBuffer) + \
        #   str(len(selectorsBuffer)))
        #exit(1)

        idxs = []
        # NEED CHANGE
        for _ in range(numSelectors):
            i = 0
            while selectorsBuffer.read('int:1'):
                i += 1
                assert(i < numTrees)
            idxs.append(i)
        #print("idxs = " + str(idxs))

        self.blockBitStream.pos = bitStreamPreservedPos + selectorsBuffer.pos

        # Selectors list is encoded with MTF, so decode it.
        selectors = self.decode_mtf(idxs, list(range(numTrees)))

        return selectors

    #@timecall
    def decode_mtf(self, idxs, stack):
        """Decode MTF symbols.

            The idea behind MTF encoding: 
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

    def parse_trees(self, numTrees, symbolStack):
        """Parse trees.
        """
        trees = []
        numSyms = len(symbolStack) + 2
        for _ in range(numTrees):
            clens = []
            clen = self.blockBitStream.read('uint:5')
            for _ in range(numSyms):
                while True:
                    assert(clen > 0 and clen <= MAX_HUFF_CODE_BITS)
                    if not self.blockBitStream.read(1):
                        break
                    clen -= +1 if self.blockBitStream.read('int:1') else -1
                clens.append(clen)
            trees.append(clens)

        return trees

    def decompress(self):
        """Decompress bz2 block."""
        #rle2Symbols = self.decode_huffman_codes(self.blockBuffer)
        rle2Symbols = self.decode_huffman_codes()
        #print("rle2Symbols = " + str(rle2Symbols) + str(len(rle2Symbols)))
        #exit(1)
        mtfSymbols = self.decode_rle2(rle2Symbols)
        #print("mtf2Symbols = " + str(mtfSymbols))
        bwtSymbols = self.decode_mtf(mtfSymbols, self.blockTrees['symbolStack'])
        #print("bwtSymbols = " + str(bwtSymbols))
        rle1Symbols = self.decode_bwt(bwtSymbols)
        #print(rle1Symbols.decode())
        decompressedSymbols = self.decode_rle1(rle1Symbols.decode())

        # check decompressed block CRC
        blockCRC = self.calc_block_crc32(decompressedSymbols)
        headerCRC = self.blockHeader['hCRC']

        # check if calculated crc of block data equals to header crc value
        if blockCRC != headerCRC:
            msg = "Calculated block CRC {} != block's header CRC {}."
            raise ValueError(msg.format(blockCRC, headerCRC))

        return decompressedSymbols

    #@timecall
    #@profile
    def decode_huffman_codes(self):
        """ Decode bits into Huffman coded symbols.

        1-st stage of bzip2 decompression stack.
        Decode bits of the block data by using the Huffman tables and selectors
        list obtained from block header in parse_selectors()l.
        """
        decodedSymbols = []
        symbolsCounter = 0
        #print(blockTrees['numTrees'])
        selectors = iter(self.blockTrees['selectors'])
        # symbolStack is the number of symbols in the stack from MTF stage.
        # Subtract 1 for losing the 0 symbol in the RLE2 stage and add 3 for
        # gaining RUNA, RUNB, EOB symbols
        huffSymbolStack = len(self.blockTrees['symbolStack']) - 1 + 3
        EOB = huffSymbolStack - 1
        #print("EOB = " + str(EOB))

        trees = self.blockTrees['trees']
        huffTreesData = self.create_decode_huffman_tables(trees)
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

            #huffSymbolsBuffer = bitStream.read(4967496)
            huffSymbol, huffSymbolLen = \
                self.read_huffman_coded_symbol(minLen, maxLen, limits)

            symbolsCounter -= 1

            # decode Huffman coded symbol (with bounds checking)
            huffSymbol -= bases[huffSymbolLen]

            if huffSymbol >= HUFF_SYMBOLS_MAX:
                msg = "huffSymbol {} can't be >= {}."
                raise ValueError(msg.format(huffSymbol, HUFF_SYMBOLS_MAX))

            huffSymbol = permutes[huffSymbol]
            decodedSymbols.append(huffSymbol)
            #print(huffSymbol)

        return decodedSymbols

    #timecall
    def create_decode_huffman_tables(self, trees):
        """Generate several tables which are used to decode huffman codes."""
        huffTreesData = {}
        for i, tree in enumerate(trees):
            minLen = min(tree)
            maxLen = max(tree)

            permutes = self.generate_permutes_table(minLen, maxLen, tree)
            #print("permutes = " + str(permutes))

            limits = self.generate_limits_table(minLen, maxLen, tree)
            #print("limits = " + str(limits))

            bases = self.generate_bases_table(minLen, maxLen, tree, limits)
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
    def generate_permutes_table(self, minLen, maxLen, Tree):
        """Generate permutes table.

        This is the lookup table for converting huffman coded symbols into
        decoded symbols. bases table is the amount to subtract from the value
        of a huffman symbol of a given length when using permutes.
        """
        permutes = []
        for length in range(minLen, maxLen + 1):
            for itemIdx, treeItem in enumerate(Tree):
                if treeItem == length:
                    permutes.append(itemIdx)

        return permutes

    #@timecall
    def generate_limits_table(self, minLen, maxLen, Tree):
        """Generate limits table.

        Which stores the largest symbol-coding value at each bit length, which
        is (previous limit << 1) + symbols at this level.
        """
        limits = [0] * (maxLen + 1)
        symLenCount = self.symbols_length_count(maxLen, Tree)
        vec = 0
        for length in range(minLen, maxLen + 1):
            vec += symLenCount[length]
            limits[length] = (vec << (maxLen - length)) - 1
            vec <<= 1

        return limits

    #@timecall
    def generate_bases_table(self, minLen, maxLen, Tree, limits):
        """Generate bases table.

        It stores number of symbols to ignore at each bit length, which is:
        limit - cumulative count of symbols coded for already.
        """
        bases = [0] * (maxLen + 1)
        symLenCount = self.symbols_length_count(maxLen, Tree)
        t, pp = 0, 0
        for length in range(minLen, maxLen):
            #startVal = ((limits[length] + 1) << 1)
            pp += symLenCount[length]
            t += symLenCount[length]
            pp <<= 1
            #bases[length + 1] = startVal - t
            bases[length + 1] = pp - t

        return bases

    def symbols_length_count(self, maxLen, Tree):
        """Create a list of symbol bit lengths (kind of a histogram).

        Where list's index is symbol's bit length and list's element is the
        count of such symbols.
        """
        symLenCount = [0] * (maxLen + 1)
        for treeItem in Tree:
            symLenCount[treeItem] += 1
    
        return symLenCount

    #@timecall
    def read_huffman_coded_symbol(self, minLen, maxLen, limits):
        """ Read Huffman coded symbol. """
        huffSymbol = self.blockBitStream.read('uint:{}'.format(maxLen))

        huffSymbolLen = minLen

        while huffSymbol > limits[huffSymbolLen]:
            huffSymbolLen += 1

        if huffSymbolLen > maxLen:
            msg = ("huffman symbol length {} can't be > maxLen {}. "
                "Bad bzip2 data.")
            raise ValueError(msg.format(huffSymbolLen, maxLen))
        
        #print("bitStream.pos before correction = " + str(bitStream.pos))
        self.blockBitStream.pos -= maxLen - huffSymbolLen
        #print("huffSymbol = {}, huffSymbolLen = {}".format(huffSymbol,
        #   huffSymbolLen))
        
        # Throw away extra bits
        huffSymbol >>= (maxLen - huffSymbolLen)

        #print("bitStream.pos = " + str(bitStream.pos))
        return huffSymbol, huffSymbolLen

    #@timecall
    def decode_rle2(self, rle2Symbols):
        """Decode RLE2 symbols.

        2-nd stage of bzip2 decompression stack.
        Decode RLE2 symbols by converting RUN_A and RUN_B sybmols (0 and 1)
        to run of zeroes.
        Decrement every symbol except RUN_A, RUN_B, EOB. So the resulting
        list of indexes is ready fom MTF decoding.
        """

        decodedSymbols = []
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
    			# You can make any bit pattern that way using 1 less symbol
                # than the basic or 0/1 method (except all bits 0, which would
                # use no symbols, but a run of length 0 doesn't mean anything
                # in this context). Thus space is saved.
                zeroCounter += (runPos << rle2Symbol)            
                runPos <<= 1
                #print("zeroCounter = " + str(zeroCounter))
                continue

            # When we hit the first non-run symbol after a run, we now know
    		# how many times to repeat the last literal, so append that many
    		# copies to our buffer of decoded symbols (dbuf) now.  (The last
    		# literal used is the one at the head of the mtfSymbol array.)
            if runPos:
                runPos = 0

                if len(rle2Symbols) + zeroCounter >= bwtBufferLimit:
                    msg = ("Amount of RLE2 symbols {} + amount of zeros {} "
                        "can't be >= size of block {}.")
                    raise ValueError(msg.format(len(rle2Symbols), zeroCounter, 
                        bwtBufferLimit))

                decodedSymbols.extend([0] * zeroCounter)

            # decrement every non RUNA, RUNB, EOB symbols to conform to
            # MTF alphabet
            decodedSymbols.append(rle2Symbol - 1)

        # delete EOB symbol
        del decodedSymbols[-1]

        return decodedSymbols

    #@timecall
    def decode_bwt(self, bwtSymbols):
        """Decode BWT symbols."""
        origPtr = self.blockHeader['hOrigPtr']
        #print("origPtr = " + str(origPtr))
        charsCount = self.chars_count(bwtSymbols)
        #print(charsCount)
        charsStartPos = self.chars_start_pos(charsCount)
        #print(charsStartPos)
        permBWT = self.permute_bwt(bwtSymbols, charsStartPos)
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

    def chars_count(self, bwtSymbols):
        """Count amount of every character.

        charsCount index - character value
        charsCount value - amount of characters of given value
        """
        charsCount = [0] * 256
        for bwtSymbol in bwtSymbols:
            charsCount[bwtSymbol] += 1

        return charsCount

    def chars_start_pos(self, charsCount):
        """Find every char start position of BWT data.

        charsCount gives us amount of every char occurence. Given this we
        calculate start position of every character in encoded BWT data if it
        would be sorted.
        """
        charsStartPos, n = [0] * 256, 0
        for i, v in enumerate(charsCount):
            charsStartPos[i] = n
            n += v

        return charsStartPos

    def permute_bwt(self, bwtSymbols, charsStartPos):
        perm = [0] * len(bwtSymbols)
        for i, v in enumerate(bwtSymbols):
            perm[charsStartPos[v]] = i
            #print("bwt = {}, charsStartPos[v] = {}, 
            #   perm[charsStartPos[v]] = {}".format(v, charsStartPos[v], 
            #       perm[charsStartPos[v]]))
            charsStartPos[v] += 1

        return perm

    #@timecall
    def decode_rle1(self, rle1Symbols):
        """Decode RLE1 symbols."""
        decodedSymbols = ""
        runLenByte = 0
        runCounter = 5
        prevSymbol = ''

        for curSymbol in rle1Symbols:
            runCounter -= 1

            if runCounter == 0:
                runLenByte = ord(curSymbol)
                runCounter = 5
                decodedSymbols += (prevSymbol * runLenByte)
                #print("curSymbol = {} runLenByte = {} {}".format(curSymbol, 
                #   runLenByte,
                #  prevSymbol * runLenByte))
                continue
            
            if curSymbol != prevSymbol:
                runCounter = 4
                prevSymbol = curSymbol

            decodedSymbols += curSymbol

        return decodedSymbols

    #@timecall
    def calc_block_crc32(self, decompressedBlock):
        """ Calculate crc32 of a bz2 block.
        
        why added & 0xffffffff to ~crc in return?
        without it there was the error:
        crc =   11110111 00100011 01000110 01011110
        ~crc = -11110111 00100011 01000110 01011111
        So ~crc is incorrect. Correct value should be
        ~crc =  00001000 11011100 10111001 10100001
        """
        crc = 0xffffffff

        crc32Table = init_crc32_table()
        #for i, v in enumerate(crc32Table):
        #    if (i + 1) % 8 == 0:
        #        print(hex(v))
        #    else:
        #        print(hex(v), end=' ')

        for curSym in decompressedBlock:
            crc = ((crc << 8) & 0xffffffff) ^ \
                crc32Table[(crc >> 24) ^ ord(curSym)]
            #print("crc = " + str(format(crc, 'b')))

        return ~crc & 0xffffffff


def process_options():
    """Process options and arguments."""
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
    #print("parsedOpts.start datetime format = " + str(optFromFormat))
    #print("parsedOpts.end datetime string = " + str(optTo))
    #print("parsedOpts.end datetime format = " + str(optToFormat))

    is_datetime_formats_equal(optFromFormat, optToFormat)
   
    return optFrom, optTo, parsedOpts.file, optFromFormat


def validate_datetime_string(datetimeStr):
    """Validate --from, --to datetime strings."""
    for i, datetimeFormat in enumerate(SUPPORTED_DATETIME_FORMATS):
        try:
            return (datetime.strptime(datetimeStr, datetimeFormat), 
                datetimeFormat)
        except ValueError:
            if i == len(SUPPORTED_DATETIME_FORMATS) - 1:
                msg = "Not a valid date: '{0}'.".format(datetimeStr)
                raise argparse.ArgumentTypeError(msg)
            else:
                continue


def is_datetime_formats_equal(optFromFormat, optToFormat):
    """Check if --from, --to datetime formats are the same."""
    if optFromFormat != optToFormat:
        msg = "Datetime formats of --from {} and --to {} are not equal."
        raise ValueError(msg.format(optFromFormat, optToFormat))


def is_optFrom_ge_optTo(optFrom, optTo):
    """Check if --from value >= --to value."""
    if optFrom >= optTo:
        msg = "--from value {} shouldn't be >= --to value {}."
        raise ValueError(msg.format(optFrom, optTo))


def parse_stream_header(bitStream):
    """Read stream header: HeaderMagic, Version, Level."""
    hMagic =    bitStream.read(16).bytes
    hVersion =  bitStream.read(8).bytes
    hLevel =    bitStream.read(8).bytes

    streamHeader = {    'hMagic':   hMagic,
                        'hVersion': hVersion,
                        'hLevel':   hLevel
                   }

    validate_stream_header(streamHeader)
    
    return streamHeader


def validate_stream_header(streamHeader):
    """Check if bz2 file starts with BZh['1'-'9'] (1-9 are ascii chars)."""
    if streamHeader['hMagic'] != b'BZ':
        msg = "This is not bz2 file. Stream header Magic (2B long) is not 'BZ'."
        raise StreamHeaderMagicError(msg)
    if streamHeader['hVersion'] != b'h':
        msg = "Stream header Version is not 'h'."
        raise StreamHeaderVersionError(msg)
    if streamHeader['hLevel'] < b'1' or streamHeader['hLevel'] > b'9':
        msg = "Stream header Level is not '1'-'9'."
        raise StreamHeaderLevelError(msg)


def calc_bwt_buffer_limit(streamHeaderLevel):
    """Calculate a limit of BWT data."""
    global bwtBufferLimit
    bwtBufferLimit = (streamHeaderLevel[0] - b'0'[0]) * 100000


def get_datetime_substring_from_block(decompressedBlock, datetimeFormat,
    datetimeSubstringLen, datetimeSubstringPos = 'first'):
    """Get datetime substring from a block.
    
    datetimeSubstringPos = 'first'|'last' means get the first or the last
    datetime string from a block
    """
    if datetimeSubstringPos == 'last':
        decompressedBlock = reversed(decompressedBlock)
    
    for string in decompressedBlock:
        #print(string)
        datetimeSubstringObj = find_datetime_substring_in_string(string,
            datetimeFormat, datetimeSubstringLen)
        if datetimeSubstringObj is not None:
            return datetimeSubstringObj
            
    msg = "Datetime substring with the format {} was not found in a block."
    raise ValueError(msg.format(datetimeFormat))


def find_datetime_substring_in_string(string, datetimeFormat, 
    datetimeSubstringLen):
    """Find datetime substring in a string."""
    stringLength = len(string)
    if datetimeSubstringLen > stringLength:
        return None
    stringStartPos = 0
    stringEndPos = datetimeSubstringLen
    while stringEndPos <= stringLength:
        datetimeSubstring = string[stringStartPos:stringEndPos]
        #print(datetimeSubstring)

        try:
            datetimeObj = datetime.strptime(datetimeSubstring, datetimeFormat)
        except ValueError:
            stringStartPos += 1
            stringEndPos += 1
        else:
            return datetimeObj
    
    #print(datetimeSubstring)
    return None


def is_optFrom_lt_fileFirstDatetimeObj(optFromDatetimeObj,
    fileFirstDatetimeObj):
    """Check if --from datetime value is less than the first datetime value
    of a file."""
    if optFromDatetimeObj < fileFirstDatetimeObj:
        msg = ("A datetime value of --from {} shouldn't be < the first "
            "datetime value in the file {}.")
        raise ValueError(msg.format(optFromDatetimeObj, fileFirstDatetimeObj))


def is_optTo_gt_fileLastDatetimeObj(optToDatetimeObj,
    fileLastDatetimeObj):
    """Check if --to datetime value is greater than the last datetime value
    of a file."""
    if optToDatetimeObj > fileLastDatetimeObj:
        msg = ("A datetime value of --to {} shouldn't be > the last "
            "datetime value in the file {}.")
        raise ValueError(msg.format(optToDatetimeObj, fileLastDatetimeObj))


def find_opt_from_block(fileBitStream, optFromDatetimeObj, datetimeFormat, 
    datetimeSubstringLength):
    """Find a block which contains a --from datetime value.
    
    As a log file is a kind of ordered data, binary search algo is used.
    """
    low = 0
    high = fileBitStream.len

    while low <= high:
        middle = low + (high - low) // 2
        #print("\nlow = {}, middle = {}, high = {}".format(low, middle, high))

        midBlockPos = fileBitStream.find(BLOCK_START_PATTERN, middle)[0]
        #print("Block pos = " + str(midBlockPos))
        midBlock = Bz2Block(fileBitStream)
        decompressedBlock = midBlock.decompress()
        #print("decompressedBlock = " + str(decompressedBlock))
        blockFirstDatetimeObj, \
        blockLastDatetimeObj = \
            get_first_last_datetime_values_from_block(decompressedBlock,
                                                      datetimeFormat,
                                                      datetimeSubstringLength)
        
        #print("blockFirstDatetimeObj = " + str(blockFirstDatetimeObj))
        #print("blockLastDatetimeObj = " + str(blockLastDatetimeObj))

        if optFromDatetimeObj > blockFirstDatetimeObj:
            msg = "--from {} > block first datetime value {}"
            #print(msg.format(optFromDatetimeObj, blockFirstDatetimeObj))

            if optFromDatetimeObj <= blockLastDatetimeObj:
                msg = "--from {} <= block last datetime value {}"
                #print(msg.format(optFromDatetimeObj, blockLastDatetimeObj))
                break

            msg = "--from {} > block last datetime value {}"
            #print(msg.format(optFromDatetimeObj, blockLastDatetimeObj))
            low = midBlockPos + 1

        elif optFromDatetimeObj < blockFirstDatetimeObj:
            msg = "--from {} < block first datetime value {}"
            #print(msg.format(optFromDatetimeObj, blockFirstDatetimeObj))
            high = middle - 1
        
        else:
            msg = "--from {} == block first datetime value {}"
            #print(msg.format(optFromDatetimeObj, blockFirstDatetimeObj))
            break
    
    return decompressedBlock, blockLastDatetimeObj, midBlockPos


def init_crc32_table():
    """Initialize CRC32 table.

    Understanding CRC32:
    https://github.com/Michaelangel007/crc32
    http://www.sunshine2k.de/articles/coding/crc/understanding_crc.html
    """
    # generator polynomial
    POLY = 0x04c11db7
    crc32Table = []

    for i in range(256):
        crc = i << 24
        for _ in range(8):
            crc = (crc << 1) ^ POLY if (crc & 0x80000000) else (crc << 1)
        crc32Table.append(crc & 0xffffffff)
    
    return crc32Table


def get_first_last_datetime_values_from_block(decompressedBlock, datetimeFormat,
    datetimeSubstringLength):
    """Get first and last datetime values from a block."""
    decompressedBlock = decompressedBlock.splitlines()
    blockFirstDatetimeObj = \
        get_datetime_substring_from_block(decompressedBlock,
                                          datetimeFormat, 
                                          datetimeSubstringLength, 
                                          'first')
    blockLastDatetimeObj = \
        get_datetime_substring_from_block(decompressedBlock,
                                          datetimeFormat,
                                          datetimeSubstringLength,
                                          'last')
    
    return blockFirstDatetimeObj, blockLastDatetimeObj


#@timecall
def main():
    """Specify main workflow of a program."""
    optFromDatetimeObj, optToDatetimeObj, optFile, datetimeFormat = \
         process_options()
    is_optFrom_ge_optTo(optFromDatetimeObj, optToDatetimeObj)

    fileBitStream = bitstring.ConstBitStream(optFile)
    
    streamHeader = parse_stream_header(fileBitStream)
    
    calc_bwt_buffer_limit(streamHeader['hLevel'])
    
    datetimeSubstringLength = len(optFromDatetimeObj.strftime(datetimeFormat))
    #print("datetimeSubstringLength = " + str(datetimeSubstringLength))

    #firstBlockPos = FIRST_BLOCK_POS
    #print("\nFirst block position = " + str(firstBlockPos))
    firstBlock = Bz2Block(fileBitStream)
    #print(first_block.decompress(bitStream))
    firstDecompressedBlock = firstBlock.decompress()
    firstBlockFirstDatetimeObj, \
    firstBlockLastDatetimeObj = \
        get_first_last_datetime_values_from_block(firstDecompressedBlock, 
                                                  datetimeFormat,
                                                  datetimeSubstringLength) 
    
    #print("First block first datetime value = " + \
    #   str(firstBlockFirstDatetimeObj))
    #print("First block last datetime value = " + \
    #   str(firstBlockLastDatetimeObj))
    fileFirstDatetimeObj = firstBlockFirstDatetimeObj
    is_optFrom_lt_fileFirstDatetimeObj(optFromDatetimeObj, fileFirstDatetimeObj)

    # Find last block position (in bits) and move file bit stream position
    # there.
    lastBlockPos = fileBitStream.rfind(BLOCK_START_PATTERN)[0]
    #print("Last block position = {}".format(lastBlockPos))
    lastBlock = Bz2Block(fileBitStream)
    #print("bitStream.pos = " + str(bitStream.pos))
    lastDecompressedBlock = lastBlock.decompress()
    lastBlockFirstDatetimeObj, \
    lastBlockLastDatetimeObj = \
        get_first_last_datetime_values_from_block(lastDecompressedBlock, 
                                                 datetimeFormat,
                                                 datetimeSubstringLength)
    #print("Last block first datetime value = " + \
    #   str(lastBlockFirstDatetimeObj))
    #print("Last block last datetime value = " + str(lastBlockLastDatetimeObj))
    fileLastDatetimeObj = lastBlockLastDatetimeObj
    is_optTo_gt_fileLastDatetimeObj(optToDatetimeObj, fileLastDatetimeObj)
    
    optFromDecompressedBlock = None
    if optFromDatetimeObj <= firstBlockLastDatetimeObj:
        optFromDecompressedBlock = firstDecompressedBlock
        print(firstDecompressedBlock, end='')
        blockLastDatetimeObj = firstBlockLastDatetimeObj
        optFromBlockPos = FIRST_BLOCK_POS
    elif optFromDatetimeObj > lastBlockFirstDatetimeObj:
        print(lastDecompressedBlock)
        return 0
    elif optFromDatetimeObj == lastBlockFirstDatetimeObj:
        #print("optFromDatetimeObj == lastBlockFirstDatetimeObj")
        # Find penultimate block
        fileBitStream.rfind(BLOCK_START_PATTERN, 0, lastBlockPos - 1)
        prelastBlock = Bz2Block(fileBitStream)
        optFromDecompressedBlock = prelastBlock.decompress()
        print(optFromDecompressedBlock, lastDecompressedBlock, sep='')
        return 0

    # Search for a block where --from datetime value is located
    if not optFromDecompressedBlock:
        optFromDecompressedBlock, \
        blockLastDatetimeObj, \
        optFromBlockPos = find_opt_from_block(fileBitStream, 
            optFromDatetimeObj, datetimeFormat, datetimeSubstringLength)
        print(optFromDecompressedBlock, end='')

    optToBlockPos = optFromBlockPos
    while optToDatetimeObj >= blockLastDatetimeObj:
        optToBlockPos = fileBitStream.find(BLOCK_START_PATTERN, 
            optToBlockPos + 1)[0]
        optToBlock = Bz2Block(fileBitStream)
        decompressedBlock = optToBlock.decompress()
        #print("bit pos = " + str(fileBitStream.pos))
        blockFirstDatetimeObj, \
        blockLastDatetimeObj = \
            get_first_last_datetime_values_from_block(decompressedBlock,
                                                      datetimeFormat,
                                                      datetimeSubstringLength)
        #print(optToBlockPos)
        print(decompressedBlock, sep='', end='')

    return 0


if __name__ == '__main__':
    sys.exit(main())