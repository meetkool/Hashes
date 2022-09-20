#include <bitset>
#include <cassert>
#include <cctype>
#include <cmath>
#include <climits>
#include <cstdint>
#include "hashes.h"
#include <iomanip>
#include <iostream>
#include <string>

using namespace std;

/*
  128 bit unsigned integer type used for hashes that work with
  much larger numbers

  Used in:
  - SHA384, SHA512, SHA512/224, SHA512/256
*/
typedef unsigned int uint128_t __attribute__((mode(TI)));

const uint128_t bigModulo = 18446744073709551615 + 1; // Used to handle modulo 2^64
                                                      // operations

/*
  Performs a rotational right shift on the bits of the passed 32 bit word

  Used in:
  - SHA256
*/
void rotationalRightShift(bool word[32], uint32_t val, unsigned int count) {
  const unsigned int mask = (CHAR_BIT*sizeof(val) - 1);

  count &= mask;

  uint32_t rotVal = (val >> count) | (val << ( (-count) & mask ));

  short wordPos = 0;
  for(short bitPos = 31; bitPos >= 0; --bitPos) {
    bool bit = rotVal & (1l << bitPos);

    word[wordPos++] = bit;
  }
}

/*
  Performs a rotational right shift on the bits of the passed 64 bit word

  Used in:
  - SHA384, SHA512, SHA512/224, SHA512/256
*/
void rotationalRightShift64(bool word[64], uint64_t val, unsigned int count) {
  const unsigned int mask = (CHAR_BIT*sizeof(val) - 1);

  count &= mask;

  uint64_t rotVal = (val >> count) | (val << ( (-count) & mask ));

  short wordPos = 0;
  for(short bitPos = 63; bitPos >= 0; --bitPos) {
    bool bit = rotVal & (1l << bitPos);

    word[wordPos++] = bit;
  }
}

/*
  Performs a rotational left shift on the bits of the passed word

  Used in:
  - MD4, SHA0, SHA1
*/
void rotationalLeftShift(bool word[32], uint32_t val, unsigned int count) {
  const unsigned int mask = (CHAR_BIT*sizeof(val) - 1);

  count &= mask;

  uint32_t rotVal = (val << count) | (val >> ( (-count) & mask));

  short wordPos = 0;
  for(short bitPos = 31; bitPos >= 0; --bitPos) {
    bool bit = rotVal & (1l << bitPos);

    word[wordPos++] = bit;
  }
}

/*
  Takes 3 32 bit words and outputs a 32 bit word by performing the following
  operation on the passed words

  (x and y) or (not x and z)

  Used in:
  - MD4, MD5, SHA0
*/
void oldChoice(bool word[32], uint32_t val1, uint32_t val2, uint32_t val3) {
  uint32_t result = (val1 & val2) | ( (~val1) & val3);

  short wordPos = 0;
  for(int bitPos = 31; bitPos >= 0; --bitPos) {
    bool bit = result & (1l << bitPos);

    word[wordPos++] = bit;
  }
}

/*
  Takes 3 32 bit words and outputs a 32 bit word by performing the following
  operation on the passed words

  (x and z) or (y and not z)

  Used in:
  - MD5
*/
void choiceVariant(bool word[32], uint32_t val1, uint32_t val2, uint32_t val3) {
  uint32_t result = (val1 & val3) | (val2 & ~(val3) );

  short wordPos = 0;
  for(int bitPos = 31; bitPos >= 0; --bitPos) {
    bool bit = result & (1l << bitPos);

    word[wordPos++] = bit;
  }
}

/*
  Takes 3 32 bit words and outputs a 32 bit word by performing the following
  operation on the passed words

  y xor (x or not z)

  Used in:
  - MD5
*/
void weirdChoiceVariant(bool word[32], uint32_t val1, uint32_t val2, uint32_t val3) {
  uint32_t result = val2 ^ ( val1 | ~(val3) );

  short wordPos = 0;
  for(int bitPos = 31; bitPos >= 0; --bitPos) {
    bool bit = result & (1l << bitPos);

    word[wordPos++] = bit;
  }
}

/*
  Takes 3 32 bit words and outputs a 32 bit word by performing the following
  operation on the passed words

  (x and y) xor (not x and z)

  Used in:
  - SHA1, SHA256
*/
void choice(bool word[32], uint32_t val1, uint32_t val2, uint32_t val3) {
  uint32_t result = (val1 & val2) ^ ( (~val1) & val3);

  short wordPos = 0;
  for(int bitPos = 31; bitPos >= 0; --bitPos) {
    bool bit = result & (1l << bitPos);

    word[wordPos++] = bit;
  }
}

/*
  Takes 3 64 bit words and outputs a 64 bit word by performing the following
  operation on the passed words

  (x and y) xor (not x and z)

  Used in:
  - SHA384, SHA512, SHA512/224, SHA512/256
*/
void choice64(bool word[64], uint64_t val1, uint64_t val2, uint64_t val3) {
  uint64_t result = (val1 & val2) ^ ( (~val1) & val3);

  short wordPos = 0;
  for(int bitPos = 63; bitPos >= 0; --bitPos) {
    bool bit = result & (1l << bitPos);

    word[wordPos++] = bit;
  }
}

/*
  Takes 3 32 bit words and outputs a 32 bit word by performing the following
  operation on the passed words

  (x and y) or (x and z) or (y and z)

  Used in:
  - MD4, SHA0
*/
void oldMajority(bool word[32], uint32_t val1, uint32_t val2, uint32_t val3) {
  uint32_t result = (val1 & val2) | (val1 & val3) | (val2 & val3);

  short wordPos = 0;
  for(int bitPos = 31; bitPos >= 0; --bitPos) {
    bool bit = result & (1l << bitPos);

    word[wordPos++] = bit;
  }
}

/*
  Takes 3 32 bit words and outputs a 32 bit word by performing the following
  operation on the passed words

  (x and y) xor (x and z) xor (y and z)

  Used in:
  - SHA1, SHA256
*/
void majority(bool word[32], uint32_t val1, uint32_t val2, uint32_t val3) {
  uint32_t result = (val1 & val2) ^ (val1 & val3) ^ (val2 & val3);

  short wordPos = 0;
  for(int bitPos = 31; bitPos >= 0; --bitPos) {
    bool bit = result & (1l << bitPos);

    word[wordPos++] = bit;
  }
}

/*
  Takes 3 64 bit words and outputs a 64 bit word by performing the following
  operation on the passed words

  (x and y) xor (x and z) xor (y and z)

  Used in:
  - SHA384, SHA512, SHA512/224, SHA512/256
*/
void majority64(bool word[64], uint64_t val1, uint64_t val2, uint64_t val3) {
  uint64_t result = (val1 & val2) ^ (val1 & val3) ^ (val2 & val3);

  short wordPos = 0;
  for(int bitPos = 63; bitPos >= 0; --bitPos) {
    bool bit = result & (1ull << bitPos);

    word[wordPos++] = bit;
  }
}

/*
  Takes 3 32 bit words and outputs a 32 bit word by performing the following
  operation on the passed words

  x xor y xor z

  Used in:
  - MD4, MD5, SHA0, SHA1
*/
void parity(bool word[32], uint32_t val1, uint32_t val2, uint32_t val3) {
  uint32_t result = val1 ^ val2 ^ val3;

  short wordPos = 0;
  for(int bitPos = 31; bitPos >= 0; --bitPos) {
    bool bit = result & (1l << bitPos);

    word[wordPos++] = bit;
  }
}

/*
  Used by the following hash algorithms

  - MD2, MD4, MD5
*/
string hexDigest(uint8_t registers[], short size) {
  string hashDigest = "";

  short bitCount = 3;
  unsigned short val = 0;
  for(short registerNum = 0; registerNum < size; ++registerNum) {
    uint8_t word = registers[registerNum];

    for(short bits = 7; bits >= 0; --bits) {
      bool bit = word & (1 << bits);

      if(bit)
        val += 1 << bitCount;

      --bitCount;
      if (bitCount == -1) {
        switch (val) {
          case 0:
          case 1:
          case 2:
          case 3:
          case 4:
          case 5:
          case 6:
          case 7:
          case 8:
          case 9:
            char num[1 + sizeof(char)];
            sprintf(num, "%d", val);

            hashDigest.append(num);
            break;

          case 10:
            hashDigest.append("a");
            break;

          case 11:
            hashDigest.append("b");
            break;

          case 12:
            hashDigest.append("c");
            break;

          case 13:
            hashDigest.append("d");
            break;

          case 14:
            hashDigest.append("e");
            break;

          case 15:
            hashDigest.append("f");
        }

        val = 0;
        bitCount = 3;
      }
    }
  }

  return hashDigest;
}

/*
  Used by the following hash algorithms

  - SHA0, SHA1, SHA224, SHA256
*/
string hexDigest(uint32_t registers[], short size) {
  string hashDigest = "";

  short bitCount = 3;
  unsigned short val = 0;
  for(short registerNum = 0; registerNum < size; ++registerNum) {
    uint32_t word = registers[registerNum];

    for(short bits = 31; bits >= 0; --bits) {
      bool bit = word & (1ull << bits);

      if(bit)
        val += 1 << bitCount;

      --bitCount;
      if (bitCount == -1) {
        switch (val) {
          case 0:
          case 1:
          case 2:
          case 3:
          case 4:
          case 5:
          case 6:
          case 7:
          case 8:
          case 9:
            char num[1 + sizeof(char)];
            sprintf(num, "%d", val);

            hashDigest.append(num);
            break;

          case 10:
            hashDigest.append("a");
            break;

          case 11:
            hashDigest.append("b");
            break;

          case 12:
            hashDigest.append("c");
            break;

          case 13:
            hashDigest.append("d");
            break;

          case 14:
            hashDigest.append("e");
            break;

          case 15:
            hashDigest.append("f");
        }

        val = 0;
        bitCount = 3;
      }
    }
  }

  return hashDigest;
}

/*
  Used by the following hash algorithms

  - SHA384, SHA512, SHA512/224, SHA512/256
*/
string hexDigest(uint64_t registers[], short size) {
  string hashDigest = "";

  short bitCount = 3;
  unsigned short val = 0;
  for(short registerNum = 0; registerNum < size; ++registerNum) {
    uint64_t word = registers[registerNum];

    for(short bits = 63; bits >= 0; --bits) {
      bool bit = word & (1ull << bits);

      if(bit)
        val += 1 << bitCount;

      --bitCount;
      if (bitCount == -1) {
        switch (val) {
          case 0:
          case 1:
          case 2:
          case 3:
          case 4:
          case 5:
          case 6:
          case 7:
          case 8:
          case 9:
            char num[1 + sizeof(char)];
            sprintf(num, "%d", val);

            hashDigest.append(num);
            break;

          case 10:
            hashDigest.append("a");
            break;

          case 11:
            hashDigest.append("b");
            break;

          case 12:
            hashDigest.append("c");
            break;

          case 13:
            hashDigest.append("d");
            break;

          case 14:
            hashDigest.append("e");
            break;

          case 15:
            hashDigest.append("f");
        }

        val = 0;
        bitCount = 3;
      }
    }
  }

  return hashDigest;
}

/*---------------------------------------------------------------------------*/
/*                             Begin MD2 Section                             */
/*---------------------------------------------------------------------------*/

/*
  MD2 Algorithm designed using the specifications described in

  RFC 1319

  Published in April 1992
*/


// Create substitution table (S table) for calculating the checksum and hash
// digest
const short subTable[256] = {41, 46, 67, 201, 162, 216, 124, 1, 61, 54, 84, 161,
                             236, 240, 6, 19, 98, 167, 5, 243, 192, 199, 115, 140,
                             152, 147, 43, 217, 188, 76, 130, 202, 30, 155, 87, 60,
                             253, 212, 224, 22, 103, 66, 111, 24, 138, 23, 229, 18,
                             190, 78, 196, 214, 218, 158, 222, 73, 160, 251, 245,
                             142, 187, 47, 238, 122, 169, 104, 121, 145, 21, 178, 7,
                             63, 148, 194, 16, 137, 11, 34, 95, 33, 128, 127, 93,
                             154, 90, 144, 50, 39, 53, 62, 204, 231, 191, 247, 151,
                             3, 255, 25, 48, 179, 72, 165, 181, 209, 215, 94, 146,
                             42, 172, 86, 170, 198, 79, 184, 56, 210, 150, 164, 125,
                             182, 118, 252, 107, 226, 156, 116, 4, 241, 69, 157,
                             112, 89, 100, 113, 135, 32, 134, 91, 207, 101, 230, 45,
                             168, 2, 27, 96, 37, 173, 174, 176, 185, 246, 28, 70,
                             97, 105, 52, 64, 126, 15, 85, 71, 163, 35, 221, 81,
                             175, 58, 195, 92, 249, 206, 186, 197, 234, 38, 44, 83,
                             13, 110, 133, 40, 132, 9, 211, 223, 205, 244, 65, 129,
                             77, 82, 106, 220, 55, 200, 108, 193, 171, 250, 36,
                             225, 123, 8, 12, 189, 177, 74, 120, 136, 149, 139,
                             227, 99, 232, 109, 233, 203, 213, 254, 59, 0, 29, 57,
                             242, 239, 183, 14, 102, 88, 208, 228, 166, 119, 114,
                             248, 235, 117, 75, 10, 49, 68, 80, 180, 143, 237, 31,
                             26, 219, 153, 141, 51, 159, 17, 131, 20};


string md2(string data) {
  uint8_t hashBlock[16]; // Holds resulting hash

  /* Generate pad */

  // MD2 pads are multiples of 16 bytes (128 bits)
  // Calculate the amount of bits needed to fill pad buffer
  unsigned long padLength = data.length() * 8; // Each character in the data is 8
                                               // bits

  // Calculates the exact size the pad buffer needs to be to fit all the bits
  padLength = (128 * (padLength / 128 + 1));

  // Padding is still performed even if the original message length is a multiple
  // of 16 bytes

  // Add space for the checksum that is appended after padding
  padLength += 128;

  // Create array to represent the pad buffer of bits
  bool padBuffer[padLength];

  // Zero out pad buffer
  for(int fill = 0; fill < padLength; ++fill)
    padBuffer[fill] = 0;

  // Fill the start of the pad buffer with the bits in the data passed to be
  // hashed
  long padPos = 0;
  for(int dataPos = 0; dataPos < data.length(); ++dataPos) {
    uint8_t dataVal = data.at(dataPos);

    for(int bitPos = 7; bitPos >= 0; --bitPos) {
      padBuffer[padPos++] = dataVal & (1l << bitPos);
    }
  }

  // Add padding
  uint8_t padValue = 16 - (data.length() % 16);

  while(padPos < padLength - 128) {
    for(int bitPos = 7; bitPos >= 0; --bitPos) {
      padBuffer[padPos++] = padValue & (1l << bitPos);
    }
  }

  /* Calculate checksum */

  bool checkSum[128];
  uint8_t l = 0;

  // Zero out checksum array
  for(short checkPos = 127; checkPos >= 0; --checkPos)
    checkSum[checkPos] = 0;

  long blocks = ceil(padLength / 128.0) - 1;
  uint8_t byte = 0;
  short checkPos = 0;
  int msgPos = 0;
  short bitCount = 7;
  for(long block = 0; block < blocks; ++block) {
    for(short msgCount = 0; msgCount < 128; ++msgCount) {
      if(padBuffer[msgPos++])
        byte += 1 << bitCount;
      --bitCount;

      if(bitCount == -1) {
        uint8_t checkVal = 0;
        for(short count = 7; count >= 0; --count)
          if(checkSum[checkPos++])
            checkVal += 1 << count;

        checkPos -= 8;

        l = subTable[byte ^ l] ^ checkVal;
        for(short count = 7; count >= 0; --count)
          checkSum[checkPos++] = l & (1 << count);

        bitCount = 7;
        byte = 0;
      }
    }
    checkPos = 0;
  }

  checkPos = 0;

  // Append checksum to pad buffer
  while(padPos < padLength)
    padBuffer[padPos++] = checkSum[checkPos++];

  /* Process pad buffer in 16 byte (128 bit) blocks */

  bool messageDigest[384];

  // Zero out message digest
  for(short count = 384; count >= 0; --count)
    messageDigest[count] = 0;

  // Process every 128 bit block
  bitCount = 7;
  uint8_t temp1 = 0;
  uint8_t temp2 = 0;
  for(long block = 0; block <= blocks; ++block) {
    // Copy current block into message digest
    for(short blockBit = 0; blockBit < 128; ++blockBit) {
      bool bit = padBuffer[block * 128 + blockBit];
      messageDigest[128 + blockBit] = bit;

      if(bit)
        temp1 += 1l << bitCount;

      if(messageDigest[blockBit])
        temp2 += 1l << bitCount;

      --bitCount;

      if(bitCount == -1) {
        uint8_t temp3 = temp1 ^ temp2;

        for(short pos = 7; pos >= 0; --pos) {
          bool bit = temp3 & (1l << pos);
          messageDigest[256 + (blockBit - pos)] = bit;
        }

        bitCount = 7;
        temp1 = 0;
        temp2 = 0;
      }
    }

    uint8_t t = 0;

    // Process 18 rounds of compression
    bitCount = 7;
    uint8_t digestByte = 0;
    for(short round = 0; round < 18; ++round) {
      // Run round
      for(short processBit = 0; processBit < 384; ++processBit) {
        if(messageDigest[processBit])
          digestByte += 1l << bitCount;
        --bitCount;

        if(bitCount == -1) {
          uint8_t temp = digestByte ^ subTable[t];

          // Set t and the current byte in the digest to the temp value
          // generated

          t = temp;

          bitCount = 7;
          uint8_t test = 0;
          for(short messagePnt = processBit - 7; messagePnt <= processBit; ++messagePnt) {
            bool bit = temp & (1l << bitCount);
            if(bit)
              test += 1l << bitCount;

            messageDigest[messagePnt] = temp & (1l << bitCount);
            --bitCount;
          }

          bitCount = 7;
          digestByte = 0;
        }
      }

      // set t to (t + round) % 256
      t = ((int)t + round) % 256;
    }
  }

  // Create state register array for the resulting 16 bytes from the start
  // of the message digest to create hex digest output
  bitCount = 7;
  byte = 0;
  short hashPos = 0;
  for(short bit = 0; bit < 128; ++bit) {
    if(messageDigest[bit])
      byte += 1l << bitCount;
    --bitCount;

    if(bitCount == -1) {
      hashBlock[hashPos] = byte;
      ++hashPos;

      byte = 0;
      bitCount = 7;
    }
  }

  return hexDigest(hashBlock, 16);
}

/*---------------------------------------------------------------------------*/
/*                             Begin MD4 Section                             */
/*---------------------------------------------------------------------------*/

/*
  MD4 Algorithm designed using the specifications described in

  RFC 1320

  Published in April 1992
*/

// Translates 32 or 64 bit binary word into numerical representation
unsigned long translateWord(bool word[], unsigned int size) {
  unsigned long temp = 0;

  short bitTrack = 0;
  for(short wordTrack = (size - 1); wordTrack >= 0; --wordTrack) {
    if(word[wordTrack])
      temp += 1l << bitTrack;
    ++bitTrack;
  }

  return temp;
}

void md4processBlock(bool block[512], uint32_t stateRegisters[4]) {
  // Translate block into an array of 16 32 bit words, taking each 32 bit
  // value's bytes and rearranging them into little endian convention
  uint32_t wordArray[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

  short wordTrack = 0;
  short bitTrack = 31;
  uint32_t temp = 0;
  for(int blockTrack = 0; blockTrack < 512; ++blockTrack) {
    if(block[blockTrack])
      temp += 1l << bitTrack;
    --bitTrack;

    if(bitTrack == -1) {
      temp = __builtin_bswap32(temp);
      wordArray[wordTrack++] = temp;
      temp = 0;
      bitTrack = 31;
    }
  }

  // Used to contain values that have been processed
  unsigned long workingVal = 0;
  bool workingWord[32];

  /* Round 1 Operations Start */

  // A = rotationalLeftShift((A + oldChoice(B, C, D) + blockWord[0]) % 4294967296, 3)
  oldChoice(workingWord, stateRegisters[1], stateRegisters[2], stateRegisters[3]);
  workingVal = stateRegisters[0] + translateWord(workingWord, 32) + wordArray[0];
  temp = workingVal % 4294967296;
  rotationalLeftShift(workingWord, temp, 3);
  workingVal = translateWord(workingWord, 32);
  stateRegisters[0] = (uint32_t)workingVal;

  // D = rotationalLeftShift((D + oldChoice(A, B, C) + blockWord[1]) % 4294967296, 7)
  oldChoice(workingWord, stateRegisters[0], stateRegisters[1], stateRegisters[2]);
  workingVal = stateRegisters[3] + translateWord(workingWord, 32) + wordArray[1];
  temp = workingVal % 4294967296;
  rotationalLeftShift(workingWord, temp, 7);
  workingVal = translateWord(workingWord, 32);
  stateRegisters[3] = (uint32_t)workingVal;

  // C = rotationalLeftShift((C + oldChoice(D, A, B) + blockWord[2]) % 4294967296, 11)
  oldChoice(workingWord, stateRegisters[3], stateRegisters[0], stateRegisters[1]);
  workingVal = stateRegisters[2] + translateWord(workingWord, 32) + wordArray[2];
  temp = workingVal % 4294967296;
  rotationalLeftShift(workingWord, temp, 11);
  workingVal = translateWord(workingWord, 32);
  stateRegisters[2] = (uint32_t)workingVal;

  // B = rotationalLeftShift((B + oldChoice(C, D, A) + blockWord[3]) % 4294967296, 19)
  oldChoice(workingWord, stateRegisters[2], stateRegisters[3], stateRegisters[0]);
  workingVal = stateRegisters[1] + translateWord(workingWord, 32) + wordArray[3];
  temp = workingVal % 4294967296;
  rotationalLeftShift(workingWord, temp, 19);
  workingVal = translateWord(workingWord, 32);
  stateRegisters[1] = (uint32_t)workingVal;

  // A = rotationalLeftShift((A + oldChoice(B, C, D) + blockWord[4]) % 4294967296, 3)
  oldChoice(workingWord, stateRegisters[1], stateRegisters[2], stateRegisters[3]);
  workingVal = stateRegisters[0] + translateWord(workingWord, 32) + wordArray[4];
  temp = workingVal % 4294967296;
  rotationalLeftShift(workingWord, temp, 3);
  workingVal = translateWord(workingWord, 32);
  stateRegisters[0] = (uint32_t)workingVal;

  // D = rotationalLeftShift((D + oldChoice(A, B, C) + blockWord[5]) % 4294967296, 7)
  oldChoice(workingWord, stateRegisters[0], stateRegisters[1], stateRegisters[2]);
  workingVal = stateRegisters[3] + translateWord(workingWord, 32) + wordArray[5];
  temp = workingVal % 4294967296;
  rotationalLeftShift(workingWord, temp, 7);
  workingVal = translateWord(workingWord, 32);
  stateRegisters[3] = (uint32_t)workingVal;

  // C = rotationalLeftShift((C + oldChoice(D, A, B) + blockWord[6]) % 4294967296, 11)
  oldChoice(workingWord, stateRegisters[3], stateRegisters[0], stateRegisters[1]);
  workingVal = stateRegisters[2] + translateWord(workingWord, 32) + wordArray[6];
  temp = workingVal % 4294967296;
  rotationalLeftShift(workingWord, temp, 11);
  workingVal = translateWord(workingWord, 32);
  stateRegisters[2] = (uint32_t)workingVal;

  // B = rotationalLeftShift((B + oldChoice(C, D, A) + blockWord[7]) % 4294967296, 19)
  oldChoice(workingWord, stateRegisters[2], stateRegisters[3], stateRegisters[0]);
  workingVal = stateRegisters[1] + translateWord(workingWord, 32) + wordArray[7];
  temp = workingVal % 4294967296;
  rotationalLeftShift(workingWord, temp, 19);
  workingVal = translateWord(workingWord, 32);
  stateRegisters[1] = (uint32_t)workingVal;

  // A = rotationalLeftShift((A + oldChoice(B, C, D) + blockWord[8]) % 4294967296, 3)
  oldChoice(workingWord, stateRegisters[1], stateRegisters[2], stateRegisters[3]);
  workingVal = stateRegisters[0] + translateWord(workingWord, 32) + wordArray[8];
  temp = workingVal % 4294967296;
  rotationalLeftShift(workingWord, temp, 3);
  workingVal = translateWord(workingWord, 32);
  stateRegisters[0] = (uint32_t)workingVal;

  // D = rotationalLeftShift((D + oldChoice(A, B, C) + blockWord[9]) % 4294967296, 7)
  oldChoice(workingWord, stateRegisters[0], stateRegisters[1], stateRegisters[2]);
  workingVal = stateRegisters[3] + translateWord(workingWord, 32) + wordArray[9];
  temp = workingVal % 4294967296;
  rotationalLeftShift(workingWord, temp, 7);
  workingVal = translateWord(workingWord, 32);
  stateRegisters[3] = (uint32_t)workingVal;

  // C = rotationalLeftShift((C + oldChoice(D, A, B) + blockWord[10]) % 4294967296, 11)
  oldChoice(workingWord, stateRegisters[3], stateRegisters[0], stateRegisters[1]);
  workingVal = stateRegisters[2] + translateWord(workingWord, 32) + wordArray[10];
  temp = workingVal % 4294967296;
  rotationalLeftShift(workingWord, temp, 11);
  workingVal = translateWord(workingWord, 32);
  stateRegisters[2] = (uint32_t)workingVal;

  // B = rotationalLeftShift((B + oldChoice(C, D, A) + blockWord[11]) % 4294967296, 19)
  oldChoice(workingWord, stateRegisters[2], stateRegisters[3], stateRegisters[0]);
  workingVal = stateRegisters[1] + translateWord(workingWord, 32) + wordArray[11];
  temp = workingVal % 4294967296;
  rotationalLeftShift(workingWord, temp, 19);
  workingVal = translateWord(workingWord, 32);
  stateRegisters[1] = (uint32_t)workingVal;

  // A = rotationalLeftShift((A + oldChoice(B, C, D) + blockWord[12]) % 4294967296, 3)
  oldChoice(workingWord, stateRegisters[1], stateRegisters[2], stateRegisters[3]);
  workingVal = stateRegisters[0] + translateWord(workingWord, 32) + wordArray[12];
  temp = workingVal % 4294967296;
  rotationalLeftShift(workingWord, temp, 3);
  workingVal = translateWord(workingWord, 32);
  stateRegisters[0] = (uint32_t)workingVal;

  // D = rotationalLeftShift((D + oldChoice(A, B, C) + blockWord[13]) % 4294967296, 7)
  oldChoice(workingWord, stateRegisters[0], stateRegisters[1], stateRegisters[2]);
  workingVal = stateRegisters[3] + translateWord(workingWord, 32) + wordArray[13];
  temp = workingVal % 4294967296;
  rotationalLeftShift(workingWord, temp, 7);
  workingVal = translateWord(workingWord, 32);
  stateRegisters[3] = (uint32_t)workingVal;

  // C = rotationalLeftShift((C + oldChoice(D, A, B) + blockWord[14]) % 4294967296, 11)
  oldChoice(workingWord, stateRegisters[3], stateRegisters[0], stateRegisters[1]);
  workingVal = stateRegisters[2] + translateWord(workingWord, 32) + wordArray[14];
  temp = workingVal % 4294967296;
  rotationalLeftShift(workingWord, temp, 11);
  workingVal = translateWord(workingWord, 32);
  stateRegisters[2] = (uint32_t)workingVal;

  // B = rotationalLeftShift((B + oldChoice(C, D, A) + blockWord[15]) % 4294967296, 19)
  oldChoice(workingWord, stateRegisters[2], stateRegisters[3], stateRegisters[0]);
  workingVal = stateRegisters[1] + translateWord(workingWord, 32) + wordArray[15];
  temp = workingVal % 4294967296;
  rotationalLeftShift(workingWord, temp, 19);
  workingVal = translateWord(workingWord, 32);
  stateRegisters[1] = (uint32_t)workingVal;

  /* Round 1 Operations Finish */

  /* Round 2 Operations Start */

  // A = rotationalLeftShift((A + oldMajority(B, C, D) + blockWord[0] + 1518500249) % 4294967296, 3)
  oldMajority(workingWord, stateRegisters[1], stateRegisters[2], stateRegisters[3]);
  workingVal = stateRegisters[0] + translateWord(workingWord, 32) + wordArray[0] + 1518500249;
  temp = workingVal % 4294967296;
  rotationalLeftShift(workingWord, temp, 3);
  workingVal = translateWord(workingWord, 32);
  stateRegisters[0] = (uint32_t)workingVal;

  // D = rotationalLeftShift((D + oldMajority(A, B, C) + blockWord[4] + 1518500249) % 4294967296, 5)
  oldMajority(workingWord, stateRegisters[0], stateRegisters[1], stateRegisters[2]);
  workingVal = stateRegisters[3] + translateWord(workingWord, 32) + wordArray[4] + 1518500249;
  temp = workingVal % 4294967296;
  rotationalLeftShift(workingWord, temp, 5);
  workingVal = translateWord(workingWord, 32);
  stateRegisters[3] = (uint32_t)workingVal;

  // C = rotationalLeftShift((C + oldMajority(D, A, B) + blockWord[8] + 1518500249) % 4294967296, 9)
  oldMajority(workingWord, stateRegisters[3], stateRegisters[0], stateRegisters[1]);
  workingVal = stateRegisters[2] + translateWord(workingWord, 32) + wordArray[8] + 1518500249;
  temp = workingVal % 4294967296;
  rotationalLeftShift(workingWord, temp, 9);
  workingVal = translateWord(workingWord, 32);
  stateRegisters[2] = (uint32_t)workingVal;

  // B = rotationalLeftShift((B + oldMajority(C, D, A) + blockWord[12] + 1518500249) % 4294967296, 13)
  oldMajority(workingWord, stateRegisters[2], stateRegisters[3], stateRegisters[0]);
  workingVal = stateRegisters[1] + translateWord(workingWord, 32) + wordArray[12] + 1518500249;
  temp = workingVal % 4294967296;
  rotationalLeftShift(workingWord, temp, 13);
  workingVal = translateWord(workingWord, 32);
  stateRegisters[1] = (uint32_t)workingVal;

  // A = rotationalLeftShift((A + oldMajority(B, C, D) + blockWord[1] + 1518500249) % 4294967296, 3)
  oldMajority(workingWord, stateRegisters[1], stateRegisters[2], stateRegisters[3]);
  workingVal = stateRegisters[0] + translateWord(workingWord, 32) + wordArray[1] + 1518500249;
  temp = workingVal % 4294967296;
  rotationalLeftShift(workingWord, temp, 3);
  workingVal = translateWord(workingWord, 32);
  stateRegisters[0] = (uint32_t)workingVal;

  // D = rotationalLeftShift((D + oldMajority(A, B, C) + blockWord[5] + 1518500249) % 4294967296, 5)
  oldMajority(workingWord, stateRegisters[0], stateRegisters[1], stateRegisters[2]);
  workingVal = stateRegisters[3] + translateWord(workingWord, 32) + wordArray[5] + 1518500249;
  temp = workingVal % 4294967296;
  rotationalLeftShift(workingWord, temp, 5);
  workingVal = translateWord(workingWord, 32);
  stateRegisters[3] = (uint32_t)workingVal;

  // C = rotationalLeftShift((C + oldMajority(D, A, B) + blockWord[9] + 1518500249) % 4294967296, 9)
  oldMajority(workingWord, stateRegisters[3], stateRegisters[0], stateRegisters[1]);
  workingVal = stateRegisters[2] + translateWord(workingWord, 32) + wordArray[9] + 1518500249;
  temp = workingVal % 4294967296;
  rotationalLeftShift(workingWord, temp, 9);
  workingVal = translateWord(workingWord, 32);
  stateRegisters[2] = (uint32_t)workingVal;

  // B = rotationalLeftShift((B + oldMajority(C, D, A) + blockWord[13] + 1518500249) % 4294967296, 13)
  oldMajority(workingWord, stateRegisters[2], stateRegisters[3], stateRegisters[0]);
  workingVal = stateRegisters[1] + translateWord(workingWord, 32) + wordArray[13] + 1518500249;
  temp = workingVal % 4294967296;
  rotationalLeftShift(workingWord, temp, 13);
  workingVal = translateWord(workingWord, 32);
  stateRegisters[1] = (uint32_t)workingVal;

  // A = rotationalLeftShift((A + oldMajority(B, C, D) + blockWord[2] + 1518500249) % 4294967296, 3)
  oldMajority(workingWord, stateRegisters[1], stateRegisters[2], stateRegisters[3]);
  workingVal = stateRegisters[0] + translateWord(workingWord, 32) + wordArray[2] + 1518500249;
  temp = workingVal % 4294967296;
  rotationalLeftShift(workingWord, temp, 3);
  workingVal = translateWord(workingWord, 32);
  stateRegisters[0] = (uint32_t)workingVal;

  // D = rotationalLeftShift((D + oldMajority(A, B, C) + blockWord[6] + 1518500249) % 4294967296, 5)
  oldMajority(workingWord, stateRegisters[0], stateRegisters[1], stateRegisters[2]);
  workingVal = stateRegisters[3] + translateWord(workingWord, 32) + wordArray[6] + 1518500249;
  temp = workingVal % 4294967296;
  rotationalLeftShift(workingWord, temp, 5);
  workingVal = translateWord(workingWord, 32);
  stateRegisters[3] = (uint32_t)workingVal;

  // C = rotationalLeftShift((C + oldMajority(D, A, B) + blockWord[10] + 1518500249) % 4294967296, 9)
  oldMajority(workingWord, stateRegisters[3], stateRegisters[0], stateRegisters[1]);
  workingVal = stateRegisters[2] + translateWord(workingWord, 32) + wordArray[10] + 1518500249;
  temp = workingVal % 4294967296;
  rotationalLeftShift(workingWord, temp, 9);
  workingVal = translateWord(workingWord, 32);
  stateRegisters[2] = (uint32_t)workingVal;

  // B = rotationalLeftShift((B + oldMajority(C, D, A) + blockWord[14] + 1518500249) % 4294967296, 13)
  oldMajority(workingWord, stateRegisters[2], stateRegisters[3], stateRegisters[0]);
  workingVal = stateRegisters[1] + translateWord(workingWord, 32) + wordArray[14] + 1518500249;
  temp = workingVal % 4294967296;
  rotationalLeftShift(workingWord, temp, 13);
  workingVal = translateWord(workingWord, 32);
  stateRegisters[1] = (uint32_t)workingVal;

  // A = rotationalLeftShift((A + oldMajority(B, C, D) + blockWord[3] + 1518500249) % 4294967296, 3)
  oldMajority(workingWord, stateRegisters[1], stateRegisters[2], stateRegisters[3]);
  workingVal = stateRegisters[0] + translateWord(workingWord, 32) + wordArray[3] + 1518500249;
  temp = workingVal % 4294967296;
  rotationalLeftShift(workingWord, temp, 3);
  workingVal = translateWord(workingWord, 32);
  stateRegisters[0] = (uint32_t)workingVal;

  // D = rotationalLeftShift((D + oldMajority(A, B, C) + blockWord[7] + 1518500249) % 4294967296, 5)
  oldMajority(workingWord, stateRegisters[0], stateRegisters[1], stateRegisters[2]);
  workingVal = stateRegisters[3] + translateWord(workingWord, 32) + wordArray[7] + 1518500249;
  temp = workingVal % 4294967296;
  rotationalLeftShift(workingWord, temp, 5);
  workingVal = translateWord(workingWord, 32);
  stateRegisters[3] = (uint32_t)workingVal;

  // C = rotationalLeftShift((C + oldMajority(D, A, B) + blockWord[11] + 1518500249) % 4294967296, 9)
  oldMajority(workingWord, stateRegisters[3], stateRegisters[0], stateRegisters[1]);
  workingVal = stateRegisters[2] + translateWord(workingWord, 32) + wordArray[11] + 1518500249;
  temp = workingVal % 4294967296;
  rotationalLeftShift(workingWord, temp, 9);
  workingVal = translateWord(workingWord, 32);
  stateRegisters[2] = (uint32_t)workingVal;

  // B = rotationalLeftShift((B + oldMajority(C, D, A) + blockWord[15] + 1518500249) % 4294967296, 13)
  oldMajority(workingWord, stateRegisters[2], stateRegisters[3], stateRegisters[0]);
  workingVal = stateRegisters[1] + translateWord(workingWord, 32) + wordArray[15] + 1518500249;
  temp = workingVal % 4294967296;
  rotationalLeftShift(workingWord, temp, 13);
  workingVal = translateWord(workingWord, 32);
  stateRegisters[1] = (uint32_t)workingVal;

  /* Round 2 Operations Finish */

  /* Round 3 Operatins Start */

  // A = rotationalLeftShift((A + parity(B, C, D) + blockWord[0] + 1859775393) % 4294967296, 3)
  parity(workingWord, stateRegisters[1], stateRegisters[2], stateRegisters[3]);
  workingVal = stateRegisters[0] + translateWord(workingWord, 32) + wordArray[0] + 1859775393;
  temp = workingVal % 4294967296;
  rotationalLeftShift(workingWord, temp, 3);
  workingVal = translateWord(workingWord, 32);
  stateRegisters[0] = (uint32_t)workingVal;

  // D = rotationalLeftShift((D + parity(A, B, C) + blockWord[8] + 1859775393) % 4294967296, 9)
  parity(workingWord, stateRegisters[0], stateRegisters[1], stateRegisters[2]);
  workingVal = stateRegisters[3] + translateWord(workingWord, 32) + wordArray[8] + 1859775393;
  temp = workingVal % 4294967296;
  rotationalLeftShift(workingWord, temp, 9);
  workingVal = translateWord(workingWord, 32);
  stateRegisters[3] = (uint32_t)workingVal;

  // C = rotationalLeftShift((C + parity(D, A, B) + blockWord[4] + 1859775393) % 4294967296, 11)
  parity(workingWord, stateRegisters[3], stateRegisters[0], stateRegisters[1]);
  workingVal = stateRegisters[2] + translateWord(workingWord, 32) + wordArray[4] + 1859775393;
  temp = workingVal % 4294967296;
  rotationalLeftShift(workingWord, temp, 11);
  workingVal = translateWord(workingWord, 32);
  stateRegisters[2] = (uint32_t)workingVal;

  // B = rotationalLeftShift((B + parity(C, D, A) + blockWord[12] + 1859775393) % 4294967296, 15)
  parity(workingWord, stateRegisters[2], stateRegisters[3], stateRegisters[0]);
  workingVal = stateRegisters[1] + translateWord(workingWord, 32) + wordArray[12] + 1859775393;
  temp = workingVal % 4294967296;
  rotationalLeftShift(workingWord, temp, 15);
  workingVal = translateWord(workingWord, 32);
  stateRegisters[1] = (uint32_t)workingVal;

  // A = rotationalLeftShift((A + parity(B, C, D) + blockWord[2] + 1859775393) % 4294967296, 3)
  parity(workingWord, stateRegisters[1], stateRegisters[2], stateRegisters[3]);
  workingVal = stateRegisters[0] + translateWord(workingWord, 32) + wordArray[2] + 1859775393;
  temp = workingVal % 4294967296;
  rotationalLeftShift(workingWord, temp, 3);
  workingVal = translateWord(workingWord, 32);
  stateRegisters[0] = (uint32_t)workingVal;

  // D = rotationalLeftShift((D + parity(A, B, C) + blockWord[10] + 1859775393) % 4294967296, 9)
  parity(workingWord, stateRegisters[0], stateRegisters[1], stateRegisters[2]);
  workingVal = stateRegisters[3] + translateWord(workingWord, 32) + wordArray[10] + 1859775393;
  temp = workingVal % 4294967296;
  rotationalLeftShift(workingWord, temp, 9);
  workingVal = translateWord(workingWord, 32);
  stateRegisters[3] = (uint32_t)workingVal;

  // C = rotationalLeftShift((C + parity(D, A, B) + blockWord[6] + 1859775393) % 4294967296, 11)
  parity(workingWord, stateRegisters[3], stateRegisters[0], stateRegisters[1]);
  workingVal = stateRegisters[2] + translateWord(workingWord, 32) + wordArray[6] + 1859775393;
  temp = workingVal % 4294967296;
  rotationalLeftShift(workingWord, temp, 11);
  workingVal = translateWord(workingWord, 32);
  stateRegisters[2] = (uint32_t)workingVal;

  // B = rotationalLeftShift((B + parity(C, D, A) + blockWord[14] + 1859775393) % 4294967296, 15)
  parity(workingWord, stateRegisters[2], stateRegisters[3], stateRegisters[0]);
  workingVal = stateRegisters[1] + translateWord(workingWord, 32) + wordArray[14] + 1859775393;
  temp = workingVal % 4294967296;
  rotationalLeftShift(workingWord, temp, 15);
  workingVal = translateWord(workingWord, 32);
  stateRegisters[1] = (uint32_t)workingVal;

  // A = rotationalLeftShift((A + parity(B, C, D) + blockWord[1] + 1859775393) % 4294967296, 3)
  parity(workingWord, stateRegisters[1], stateRegisters[2], stateRegisters[3]);
  workingVal = stateRegisters[0] + translateWord(workingWord, 32) + wordArray[1] + 1859775393;
  temp = workingVal % 4294967296;
  rotationalLeftShift(workingWord, temp, 3);
  workingVal = translateWord(workingWord, 32);
  stateRegisters[0] = (uint32_t)workingVal;

  // D = rotationalLeftShift((D + parity(A, B, C) + blockWord[9] + 1859775393) % 4294967296, 9)
  parity(workingWord, stateRegisters[0], stateRegisters[1], stateRegisters[2]);
  workingVal = stateRegisters[3] + translateWord(workingWord, 32) + wordArray[9] + 1859775393;
  temp = workingVal % 4294967296;
  rotationalLeftShift(workingWord, temp, 9);
  workingVal = translateWord(workingWord, 32);
  stateRegisters[3] = (uint32_t)workingVal;

  // C = rotationalLeftShift((C + parity(D, A, B) + blockWord[5] + 1859775393) % 4294967296, 11)
  parity(workingWord, stateRegisters[3], stateRegisters[0], stateRegisters[1]);
  workingVal = stateRegisters[2] + translateWord(workingWord, 32) + wordArray[5] + 1859775393;
  temp = workingVal % 4294967296;
  rotationalLeftShift(workingWord, temp, 11);
  workingVal = translateWord(workingWord, 32);
  stateRegisters[2] = (uint32_t)workingVal;

  // B = rotationalLeftShift((B + parity(C, D, A) + blockWord[13] + 1859775393) % 4294967296, 15)
  parity(workingWord, stateRegisters[2], stateRegisters[3], stateRegisters[0]);
  workingVal = stateRegisters[1] + translateWord(workingWord, 32) + wordArray[13] + 1859775393;
  temp = workingVal % 4294967296;
  rotationalLeftShift(workingWord, temp, 15);
  workingVal = translateWord(workingWord, 32);
  stateRegisters[1] = (uint32_t)workingVal;

  // A = rotationalLeftShift((A + parity(B, C, D) + blockWord[3] + 1859775393) % 4294967296, 3)
  parity(workingWord, stateRegisters[1], stateRegisters[2], stateRegisters[3]);
  workingVal = stateRegisters[0] + translateWord(workingWord, 32) + wordArray[3] + 1859775393;
  temp = workingVal % 4294967296;
  rotationalLeftShift(workingWord, temp, 3);
  workingVal = translateWord(workingWord, 32);
  stateRegisters[0] = (uint32_t)workingVal;

  // D = rotationalLeftShift((D + parity(A, B, C) + blockWord[11] + 1859775393) % 4294967296, 9)
  parity(workingWord, stateRegisters[0], stateRegisters[1], stateRegisters[2]);
  workingVal = stateRegisters[3] + translateWord(workingWord, 32) + wordArray[11] + 1859775393;
  temp = workingVal % 4294967296;
  rotationalLeftShift(workingWord, temp, 9);
  workingVal = translateWord(workingWord, 32);
  stateRegisters[3] = (uint32_t)workingVal;

  // C = rotationalLeftShift((C + parity(D, A, B) + blockWord[7] + 1859775393) % 4294967296, 11)
  parity(workingWord, stateRegisters[3], stateRegisters[0], stateRegisters[1]);
  workingVal = stateRegisters[2] + translateWord(workingWord, 32) + wordArray[7] + 1859775393;
  temp = workingVal % 4294967296;
  rotationalLeftShift(workingWord, temp, 11);
  workingVal = translateWord(workingWord, 32);
  stateRegisters[2] = (uint32_t)workingVal;

  // B = rotationalLeftShift((B + parity(C, D, A) + blockWord[15] + 1859775393) % 4294967296, 15)
  parity(workingWord, stateRegisters[2], stateRegisters[3], stateRegisters[0]);
  workingVal = stateRegisters[1] + translateWord(workingWord, 32) + wordArray[15] + 1859775393;
  temp = workingVal % 4294967296;
  rotationalLeftShift(workingWord, temp, 15);
  workingVal = translateWord(workingWord, 32);
  stateRegisters[1] = (uint32_t)workingVal;

  /* Round 3 Operations Finish */

}

string md4(string data) {
  // Calculate the amount of bits needed to fill pad buffer
  unsigned long padLength = data.length() * 8; // Each character in the data is 8
                                               // bits
  unsigned long lengthHolder = padLength; // Saved for later to add to the end
                                          // of the pad buffer

  // Calculates the exact size the pad buffer needs to be to fit all the bits
  padLength = (512 * (padLength / 512 + 1));

  if(lengthHolder + 1 > padLength - 64)
    padLength += 512;

  // Create array to represent the pad buffer of bits
  bool padBuffer[padLength];

  // Zero out pad buffer
  for(int fill = 0; fill < padLength; ++fill)
    padBuffer[fill] = 0;

  /* Fill pad buffer */
  // Fill with bits taken from every byte of the given data
  int padPos = 0;
  for(int dataPos = 0; dataPos < data.length(); ++dataPos) {
    uint8_t dataVal = data.at(dataPos);

    for(int bitPos = 7; bitPos >= 0; --bitPos) {
      padBuffer[padPos] = dataVal & (1l << bitPos);
      ++padPos;
    }
  }

  // Add a 1 bit
  padBuffer[padPos] = 1;

  padPos = padLength - 64;

  // Fill pad with 0s until 64 bits of space remain:
  // This is already done after we initialize the array
  // since we zero it out to get rid of any garbage left
  // in memory

  // Create a byte array using the individual bytes of the saved message length
  // before padding, using little endian convention
  uint64_t val = lengthHolder;

  uint8_t byteArray[8] = {0, 0, 0, 0, 0, 0, 0, 0};

  for(short byte = 0; byte < 8; ++byte)
    switch(byte) {
      case 0:
        byteArray[byte] = (lengthHolder >> 0) & 255;
        break;

      case 1:
        byteArray[byte] = (lengthHolder >> 8) & 255;
        break;

      case 2:
        byteArray[byte] = (lengthHolder >> 16) & 255;
        break;

      case 3:
        byteArray[byte] = (lengthHolder >> 24) & 255;
        break;

      case 4:
        byteArray[byte] = (lengthHolder >> 32) & 255;
        break;

      case 5:
        byteArray[byte] = (lengthHolder >> 40) & 255;
        break;

      case 6:
        byteArray[byte] = (lengthHolder >> 48) & 255;
        break;

      case 7:
        byteArray[byte] = (lengthHolder >> 56) & 255;
    }

  // Append byte array into the remaining space of the pad buffer as individual
  // bits
  for(uint8_t val: byteArray)
    for(short bitPos = 7; bitPos >= 0; --bitPos) {
      bool bit = val & (1l << bitPos);

      padBuffer[padPos++] = bit;
    }

  // Create and fill initial state registers
  uint32_t registers[4];

  for(short count = 0; count < 4; ++count)
    switch(count) {
      case 0:
        registers[count] = 1732584193;  // 0x67452301
        break;

      case 1:
        registers[count] = 4023233417;  // 0xefcdab89
        break;

      case 2:
        registers[count] = 2562383102;  // 0x98badcfe
        break;

      case 3:
        registers[count] = 271733878;   // 0x10325476
    }

  // Process pad buffer in 512 bit blocks
  bool block[512];

  int blockTrack = 0;
  uint32_t registerStateSave[4];

  for(int bitCount = 0; bitCount < padLength; ++bitCount) {
    block[blockTrack] = padBuffer[bitCount];
    ++blockTrack;

    if(blockTrack == 512) {
      // Save the state of the current registers
      short pos = 0;
      for (uint32_t val: registers)
        registerStateSave[pos++] = val;

      md4processBlock(block, registers);

      // Add saved register state to the newly processed register state to
      // obtain the final resulting register state of the current iteration
      unsigned long tempVal = 0;
      for(short pointer = 0; pointer < 4; ++pointer) {
        for(short bitPos = 31; bitPos >= 0; --bitPos) {
          if(registers[pointer] & (1l << bitPos))
            tempVal += 1l << bitPos;

          if(registerStateSave[pointer] & (1l << bitPos))
            tempVal += 1l << bitPos;
        }

        uint32_t newStateVal = tempVal % 4294967296;

        registers[pointer] = newStateVal;

        tempVal = 0;
      }

      blockTrack = 0;
    }
  }

  // Translate final register state values into an array of bytes, arranged in
  // little endian convention
  uint8_t digestArray[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

  short byteTracker = 0;
  for(uint32_t registerVal: registers) {
    digestArray[byteTracker++] = (registerVal >> 0) & 255;
    digestArray[byteTracker++] = (registerVal >> 8) & 255;
    digestArray[byteTracker++] = (registerVal >> 16) & 255;
    digestArray[byteTracker++] = (registerVal >> 24) & 255;
  }

  return hexDigest(digestArray, 16);
}

/*---------------------------------------------------------------------------*/
/*                             Begin MD5 Section                             */
/*---------------------------------------------------------------------------*/

/*
  MD4 Algorithm designed using the specifications described in

  RFC 1321

  Published in April 1992
*/

void md5processBlock(bool block[512], uint32_t stateRegisters[4]) {
  // Translate block into an array of 16 32 bit words, taking each 32 bit
  // value's bytes and rearranging them into little endian convention
  uint32_t wordArray[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

  short wordTrack = 0;
  short bitTrack = 31;
  uint32_t temp = 0;
  for(int blockTrack = 0; blockTrack < 512; ++blockTrack) {
    if(block[blockTrack])
      temp += 1l << bitTrack;
    --bitTrack;

    if(bitTrack == -1) {
      temp = __builtin_bswap32(temp);
      wordArray[wordTrack++] = temp;
      temp = 0;
      bitTrack = 31;
    }
  }

  // Used to contain values that have been processed
  unsigned long workingVal = 0;
  bool workingWord[32];

  short sineTrack = 1; // Tracks the value we pass to sine function

  /* Round 1 Operations Start */

  // A = B + rotationalLeftShift((A + oldChoice(B, C, D) + blockWord[0] + abs(sin(1)) * 4294967296), 7)
  oldChoice(workingWord, stateRegisters[1], stateRegisters[2], stateRegisters[3]);
  workingVal = stateRegisters[0] + translateWord(workingWord, 32) + wordArray[0] +
               (abs(sin(sineTrack++)) * 4294967296);
  temp = workingVal % 4294967296;
  rotationalLeftShift(workingWord, temp, 7);
  workingVal = (stateRegisters[1] + translateWord(workingWord, 32)) % 4294967296;
  stateRegisters[0] = (uint32_t)workingVal;

  // D = A + rotationalLeftShift((D + oldChoice(A, B, C) + blockWord[1] + abs(sin(2)) * 4294967296), 12)
  oldChoice(workingWord, stateRegisters[0], stateRegisters[1], stateRegisters[2]);
  workingVal = stateRegisters[3] + translateWord(workingWord, 32) + wordArray[1] +
               (abs(sin(sineTrack++)) * 4294967296);
  temp = workingVal % 4294967296;
  rotationalLeftShift(workingWord, temp, 12);
  workingVal = (stateRegisters[0] + translateWord(workingWord, 32)) % 4294967296;
  stateRegisters[3] = (uint32_t)workingVal;

  // C = D + rotationalLeftShift((C + oldChoice(D, A, B) + blockWord[2] + abs(sin(3)) * 4294967296), 17)
  oldChoice(workingWord, stateRegisters[3], stateRegisters[0], stateRegisters[1]);
  workingVal = stateRegisters[2] + translateWord(workingWord, 32) + wordArray[2] +
               (abs(sin(sineTrack++)) * 4294967296);
  temp = workingVal % 4294967296;
  rotationalLeftShift(workingWord, temp, 17);
  workingVal = (stateRegisters[3] + translateWord(workingWord, 32)) % 4294967296;
  stateRegisters[2] = (uint32_t)workingVal;

  // B = C + rotationalLeftShift((B + oldChoice(C, D, A) + blockWord[3] + abs(sin(4)) * 4294967296), 22)
  oldChoice(workingWord, stateRegisters[2], stateRegisters[3], stateRegisters[0]);
  workingVal = stateRegisters[1] + translateWord(workingWord, 32) + wordArray[3] +
               (abs(sin(sineTrack++)) * 4294967296);
  temp = workingVal % 4294967296;
  rotationalLeftShift(workingWord, temp, 22);
  workingVal = (stateRegisters[2] + translateWord(workingWord, 32)) % 4294967296;
  stateRegisters[1] = (uint32_t)workingVal;

  // A = B + rotationalLeftShift((A + oldChoice(B, C, D) + blockWord[4] + abs(sin(5)) * 4294967296), 7)
  oldChoice(workingWord, stateRegisters[1], stateRegisters[2], stateRegisters[3]);
  workingVal = stateRegisters[0] + translateWord(workingWord, 32) + wordArray[4] +
               (abs(sin(sineTrack++)) * 4294967296);
  temp = workingVal % 4294967296;
  rotationalLeftShift(workingWord, temp, 7);
  workingVal = (stateRegisters[1] + translateWord(workingWord, 32)) % 4294967296;
  stateRegisters[0] = (uint32_t)workingVal;

  // D = A + rotationalLeftShift((D + oldChoice(A, B, C) + blockWord[5] + abs(sin(6)) * 4294967296), 12)
  oldChoice(workingWord, stateRegisters[0], stateRegisters[1], stateRegisters[2]);
  workingVal = stateRegisters[3] + translateWord(workingWord, 32) + wordArray[5] +
               (abs(sin(sineTrack++)) * 4294967296);
  temp = workingVal % 4294967296;
  rotationalLeftShift(workingWord, temp, 12);
  workingVal = (stateRegisters[0] + translateWord(workingWord, 32)) % 4294967296;
  stateRegisters[3] = (uint32_t)workingVal;

  // C = D + rotationalLeftShift((C + oldChoice(D, A, B) + blockWord[6] + abs(sin(7)) * 4294967296), 17)
  oldChoice(workingWord, stateRegisters[3], stateRegisters[0], stateRegisters[1]);
  workingVal = stateRegisters[2] + translateWord(workingWord, 32) + wordArray[6] +
               (abs(sin(sineTrack++)) * 4294967296);
  temp = workingVal % 4294967296;
  rotationalLeftShift(workingWord, temp, 17);
  workingVal = (stateRegisters[3] + translateWord(workingWord, 32)) % 4294967296;
  stateRegisters[2] = (uint32_t)workingVal;

  // B = C + rotationalLeftShift((B + oldChoice(C, D, A) + blockWord[7] + abs(sin(8)) * 4294967296), 22)
  oldChoice(workingWord, stateRegisters[2], stateRegisters[3], stateRegisters[0]);
  workingVal = stateRegisters[1] + translateWord(workingWord, 32) + wordArray[7] +
               (abs(sin(sineTrack++)) * 4294967296);
  temp = workingVal % 4294967296;
  rotationalLeftShift(workingWord, temp, 22);
  workingVal = (stateRegisters[2] + translateWord(workingWord, 32)) % 4294967296;
  stateRegisters[1] = (uint32_t)workingVal;

  // A = B + rotationalLeftShift((A + oldChoice(B, C, D) + blockWord[8] + abs(sin(9)) * 4294967296), 7)
  oldChoice(workingWord, stateRegisters[1], stateRegisters[2], stateRegisters[3]);
  workingVal = stateRegisters[0] + translateWord(workingWord, 32) + wordArray[8] +
               (abs(sin(sineTrack++)) * 4294967296);
  temp = workingVal % 4294967296;
  rotationalLeftShift(workingWord, temp, 7);
  workingVal = (stateRegisters[1] + translateWord(workingWord, 32)) % 4294967296;
  stateRegisters[0] = (uint32_t)workingVal;

  // D = A + rotationalLeftShift((D + oldChoice(A, B, C) + blockWord[9] + abs(sin(10)) * 4294967296), 12)
  oldChoice(workingWord, stateRegisters[0], stateRegisters[1], stateRegisters[2]);
  workingVal = stateRegisters[3] + translateWord(workingWord, 32) + wordArray[9] +
               (abs(sin(sineTrack++)) * 4294967296);
  temp = workingVal % 4294967296;
  rotationalLeftShift(workingWord, temp, 12);
  workingVal = (stateRegisters[0] + translateWord(workingWord, 32)) % 4294967296;
  stateRegisters[3] = (uint32_t)workingVal;

  // C = D + rotationalLeftShift((C + oldChoice(D, A, B) + blockWord[10] + abs(sin(11)) * 4294967296), 17)
  oldChoice(workingWord, stateRegisters[3], stateRegisters[0], stateRegisters[1]);
  workingVal = stateRegisters[2] + translateWord(workingWord, 32) + wordArray[10] +
               (abs(sin(sineTrack++)) * 4294967296);
  temp = workingVal % 4294967296;
  rotationalLeftShift(workingWord, temp, 17);
  workingVal = (stateRegisters[3] + translateWord(workingWord, 32)) % 4294967296;
  stateRegisters[2] = (uint32_t)workingVal;

  // B = C + rotationalLeftShift((B + oldChoice(C, D, A) + blockWord[11] + abs(sin(12)) * 4294967296), 22)
  oldChoice(workingWord, stateRegisters[2], stateRegisters[3], stateRegisters[0]);
  workingVal = stateRegisters[1] + translateWord(workingWord, 32) + wordArray[11] +
               (abs(sin(sineTrack++)) * 4294967296);
  temp = workingVal % 4294967296;
  rotationalLeftShift(workingWord, temp, 22);
  workingVal = (stateRegisters[2] + translateWord(workingWord, 32)) % 4294967296;
  stateRegisters[1] = (uint32_t)workingVal;

  // A = B + rotationalLeftShift((A + oldChoice(B, C, D) + blockWord[12] + abs(sin(13)) * 4294967296), 7)
  oldChoice(workingWord, stateRegisters[1], stateRegisters[2], stateRegisters[3]);
  workingVal = stateRegisters[0] + translateWord(workingWord, 32) + wordArray[12] +
               (abs(sin(sineTrack++)) * 4294967296);
  temp = workingVal % 4294967296;
  rotationalLeftShift(workingWord, temp, 7);
  workingVal = (stateRegisters[1] + translateWord(workingWord, 32)) % 4294967296;
  stateRegisters[0] = (uint32_t)workingVal;

  // D = A + rotationalLeftShift((D + oldChoice(A, B, C) + blockWord[13] + abs(sin(14)) * 4294967296), 12)
  oldChoice(workingWord, stateRegisters[0], stateRegisters[1], stateRegisters[2]);
  workingVal = stateRegisters[3] + translateWord(workingWord, 32) + wordArray[13] +
               (abs(sin(sineTrack++)) * 4294967296);
  temp = workingVal % 4294967296;
  rotationalLeftShift(workingWord, temp, 12);
  workingVal = (stateRegisters[0] + translateWord(workingWord, 32)) % 4294967296;
  stateRegisters[3] = (uint32_t)workingVal;

  // C = D + rotationalLeftShift((C + oldChoice(D, A, B) + blockWord[14] + abs(sin(15)) * 4294967296), 17)
  oldChoice(workingWord, stateRegisters[3], stateRegisters[0], stateRegisters[1]);
  workingVal = stateRegisters[2] + translateWord(workingWord, 32) + wordArray[14] +
               (abs(sin(sineTrack++)) * 4294967296);
  temp = workingVal % 4294967296;
  rotationalLeftShift(workingWord, temp, 17);
  workingVal = (stateRegisters[3] + translateWord(workingWord, 32)) % 4294967296;
  stateRegisters[2] = (uint32_t)workingVal;

  // B = C + rotationalLeftShift((B + oldChoice(C, D, A) + blockWord[15] + abs(sin(16)) * 4294967296), 22)
  oldChoice(workingWord, stateRegisters[2], stateRegisters[3], stateRegisters[0]);
  workingVal = stateRegisters[1] + translateWord(workingWord, 32) + wordArray[15] +
               (abs(sin(sineTrack++)) * 4294967296);
  temp = workingVal % 4294967296;
  rotationalLeftShift(workingWord, temp, 22);
  workingVal = (stateRegisters[2] + translateWord(workingWord, 32)) % 4294967296;
  stateRegisters[1] = (uint32_t)workingVal;

  /* Round 1 Operations Finish */

  /* Round 2 Operations Start */

  // A = B + rotationalLeftShift((A + choiceVariant(B, C, D) + blockWord[1] + abs(sin(17)) * 4294967296), 5)
  choiceVariant(workingWord, stateRegisters[1], stateRegisters[2], stateRegisters[3]);
  workingVal = stateRegisters[0] + translateWord(workingWord, 32) + wordArray[1] +
               (abs(sin(sineTrack++)) * 4294967296);
  temp = workingVal % 4294967296;
  rotationalLeftShift(workingWord, temp, 5);
  workingVal = (stateRegisters[1] + translateWord(workingWord, 32)) % 4294967296;
  stateRegisters[0] = (uint32_t)workingVal;

  // D = A + rotationalLeftShift((D + choiceVariant(A, B, C) + blockWord[6] + abs(sin(18)) * 4294967296), 9)
  choiceVariant(workingWord, stateRegisters[0], stateRegisters[1], stateRegisters[2]);
  workingVal = stateRegisters[3] + translateWord(workingWord, 32) + wordArray[6] +
               (abs(sin(sineTrack++)) * 4294967296);
  temp = workingVal % 4294967296;
  rotationalLeftShift(workingWord, temp, 9);
  workingVal = (stateRegisters[0] + translateWord(workingWord, 32)) % 4294967296;
  stateRegisters[3] = (uint32_t)workingVal;

  // C = D + rotationalLeftShift((C + choiceVariant(D, A, B) + blockWord[11] + abs(sin(19)) * 4294967296), 14)
  choiceVariant(workingWord, stateRegisters[3], stateRegisters[0], stateRegisters[1]);
  workingVal = stateRegisters[2] + translateWord(workingWord, 32) + wordArray[11] +
               (abs(sin(sineTrack++)) * 4294967296);
  temp = workingVal % 4294967296;
  rotationalLeftShift(workingWord, temp, 14);
  workingVal = (stateRegisters[3] + translateWord(workingWord, 32)) % 4294967296;
  stateRegisters[2] = (uint32_t)workingVal;

  // B = C + rotationalLeftShift((B + choiceVariant(C, D, A) + blockWord[0] + abs(sin(20)) * 4294967296), 20)
  choiceVariant(workingWord, stateRegisters[2], stateRegisters[3], stateRegisters[0]);
  workingVal = stateRegisters[1] + translateWord(workingWord, 32) + wordArray[0] +
               (abs(sin(sineTrack++)) * 4294967296);
  temp = workingVal % 4294967296;
  rotationalLeftShift(workingWord, temp, 20);
  workingVal = (stateRegisters[2] + translateWord(workingWord, 32)) % 4294967296;
  stateRegisters[1] = (uint32_t)workingVal;

  // A = B + rotationalLeftShift((A + choiceVariant(B, C, D) + blockWord[5] + abs(sin(21)) * 4294967296), 5)
  choiceVariant(workingWord, stateRegisters[1], stateRegisters[2], stateRegisters[3]);
  workingVal = stateRegisters[0] + translateWord(workingWord, 32) + wordArray[5] +
               (abs(sin(sineTrack++)) * 4294967296);
  temp = workingVal % 4294967296;
  rotationalLeftShift(workingWord, temp, 5);
  workingVal = (stateRegisters[1] + translateWord(workingWord, 32)) % 4294967296;
  stateRegisters[0] = (uint32_t)workingVal;

  // D = A + rotationalLeftShift((D + choiceVariant(A, B, C) + blockWord[10] + abs(sin(22)) * 4294967296), 9)
  choiceVariant(workingWord, stateRegisters[0], stateRegisters[1], stateRegisters[2]);
  workingVal = stateRegisters[3] + translateWord(workingWord, 32) + wordArray[10] +
               (abs(sin(sineTrack++)) * 4294967296);
  temp = workingVal % 4294967296;
  rotationalLeftShift(workingWord, temp, 9);
  workingVal = (stateRegisters[0] + translateWord(workingWord, 32)) % 4294967296;
  stateRegisters[3] = (uint32_t)workingVal;

  // C = D + rotationalLeftShift((C + choiceVariant(D, A, B) + blockWord[15] + abs(sin(23)) * 4294967296), 14)
  choiceVariant(workingWord, stateRegisters[3], stateRegisters[0], stateRegisters[1]);
  workingVal = stateRegisters[2] + translateWord(workingWord, 32) + wordArray[15] +
               (abs(sin(sineTrack++)) * 4294967296);
  temp = workingVal % 4294967296;
  rotationalLeftShift(workingWord, temp, 14);
  workingVal = (stateRegisters[3] + translateWord(workingWord, 32)) % 4294967296;
  stateRegisters[2] = (uint32_t)workingVal;

  // B = C + rotationalLeftShift((B + choiceVariant(C, D, A) + blockWord[4] + abs(sin(24)) * 4294967296), 20)
  choiceVariant(workingWord, stateRegisters[2], stateRegisters[3], stateRegisters[0]);
  workingVal = stateRegisters[1] + translateWord(workingWord, 32) + wordArray[4] +
               (abs(sin(sineTrack++)) * 4294967296);
  temp = workingVal % 4294967296;
  rotationalLeftShift(workingWord, temp, 20);
  workingVal = (stateRegisters[2] + translateWord(workingWord, 32)) % 4294967296;
  stateRegisters[1] = (uint32_t)workingVal;

  // A = B + rotationalLeftShift((A + choiceVariant(B, C, D) + blockWord[9] + abs(sin(25)) * 4294967296), 5)
  choiceVariant(workingWord, stateRegisters[1], stateRegisters[2], stateRegisters[3]);
  workingVal = stateRegisters[0] + translateWord(workingWord, 32) + wordArray[9] +
               (abs(sin(sineTrack++)) * 4294967296);
  temp = workingVal % 4294967296;
  rotationalLeftShift(workingWord, temp, 5);
  workingVal = (stateRegisters[1] + translateWord(workingWord, 32)) % 4294967296;
  stateRegisters[0] = (uint32_t)workingVal;

  // D = A + rotationalLeftShift((D + choiceVariant(A, B, C) + blockWord[14] + abs(sin(26)) * 4294967296), 9)
  choiceVariant(workingWord, stateRegisters[0], stateRegisters[1], stateRegisters[2]);
  workingVal = stateRegisters[3] + translateWord(workingWord, 32) + wordArray[14] +
               (abs(sin(sineTrack++)) * 4294967296);
  temp = workingVal % 4294967296;
  rotationalLeftShift(workingWord, temp, 9);
  workingVal = (stateRegisters[0] + translateWord(workingWord, 32)) % 4294967296;
  stateRegisters[3] = (uint32_t)workingVal;

  // C = D + rotationalLeftShift((C + choiceVariant(D, A, B) + blockWord[3] + abs(sin(27)) * 4294967296), 14)
  choiceVariant(workingWord, stateRegisters[3], stateRegisters[0], stateRegisters[1]);
  workingVal = stateRegisters[2] + translateWord(workingWord, 32) + wordArray[3] +
               (abs(sin(sineTrack++)) * 4294967296);
  temp = workingVal % 4294967296;
  rotationalLeftShift(workingWord, temp, 14);
  workingVal = (stateRegisters[3] + translateWord(workingWord, 32)) % 4294967296;
  stateRegisters[2] = (uint32_t)workingVal;

  // B = C + rotationalLeftShift((B + choiceVariant(C, D, A) + blockWord[8] + abs(sin(28)) * 4294967296), 20)
  choiceVariant(workingWord, stateRegisters[2], stateRegisters[3], stateRegisters[0]);
  workingVal = stateRegisters[1] + translateWord(workingWord, 32) + wordArray[8] +
               (abs(sin(sineTrack++)) * 4294967296);
  temp = workingVal % 4294967296;
  rotationalLeftShift(workingWord, temp, 20);
  workingVal = (stateRegisters[2] + translateWord(workingWord, 32)) % 4294967296;
  stateRegisters[1] = (uint32_t)workingVal;

  // A = B + rotationalLeftShift((A + choiceVariant(B, C, D) + blockWord[13] + abs(sin(29)) * 4294967296), 5)
  choiceVariant(workingWord, stateRegisters[1], stateRegisters[2], stateRegisters[3]);
  workingVal = stateRegisters[0] + translateWord(workingWord, 32) + wordArray[13] +
               (abs(sin(sineTrack++)) * 4294967296);
  temp = workingVal % 4294967296;
  rotationalLeftShift(workingWord, temp, 5);
  workingVal = (stateRegisters[1] + translateWord(workingWord, 32)) % 4294967296;
  stateRegisters[0] = (uint32_t)workingVal;

  // D = A + rotationalLeftShift((D + choiceVariant(A, B, C) + blockWord[2] + abs(sin(30)) * 4294967296), 9)
  choiceVariant(workingWord, stateRegisters[0], stateRegisters[1], stateRegisters[2]);
  workingVal = stateRegisters[3] + translateWord(workingWord, 32) + wordArray[2] +
               (abs(sin(sineTrack++)) * 4294967296);
  temp = workingVal % 4294967296;
  rotationalLeftShift(workingWord, temp, 9);
  workingVal = (stateRegisters[0] + translateWord(workingWord, 32)) % 4294967296;
  stateRegisters[3] = (uint32_t)workingVal;

  // C = D + rotationalLeftShift((C + choiceVariant(D, A, B) + blockWord[7] + abs(sin(31)) * 4294967296), 14)
  choiceVariant(workingWord, stateRegisters[3], stateRegisters[0], stateRegisters[1]);
  workingVal = stateRegisters[2] + translateWord(workingWord, 32) + wordArray[7] +
               (abs(sin(sineTrack++)) * 4294967296);
  temp = workingVal % 4294967296;
  rotationalLeftShift(workingWord, temp, 14);
  workingVal = (stateRegisters[3] + translateWord(workingWord, 32)) % 4294967296;
  stateRegisters[2] = (uint32_t)workingVal;

  // B = C + rotationalLeftShift((B + choiceVariant(C, D, A) + blockWord[12] + abs(sin(32)) * 4294967296), 20)
  choiceVariant(workingWord, stateRegisters[2], stateRegisters[3], stateRegisters[0]);
  workingVal = stateRegisters[1] + translateWord(workingWord, 32) + wordArray[12] +
               (abs(sin(sineTrack++)) * 4294967296);
  temp = workingVal % 4294967296;
  rotationalLeftShift(workingWord, temp, 20);
  workingVal = (stateRegisters[2] + translateWord(workingWord, 32)) % 4294967296;
  stateRegisters[1] = (uint32_t)workingVal;

  /* Round 2 Operations Finish */

  /* Round 3 Operations Start */

  // A = B + rotationalLeftShift((A + parity(B, C, D) + blockWord[5] + abs(sin(33)) * 4294967296), 4)
  parity(workingWord, stateRegisters[1], stateRegisters[2], stateRegisters[3]);
  workingVal = stateRegisters[0] + translateWord(workingWord, 32) + wordArray[5] +
               (abs(sin(sineTrack++)) * 4294967296);
  temp = workingVal % 4294967296;
  rotationalLeftShift(workingWord, temp, 4);
  workingVal = (stateRegisters[1] + translateWord(workingWord, 32)) % 4294967296;
  stateRegisters[0] = (uint32_t)workingVal;

  // D = A + rotationalLeftShift((D + parity(A, B, C) + blockWord[8] + abs(sin(34)) * 4294967296), 11)
  parity(workingWord, stateRegisters[0], stateRegisters[1], stateRegisters[2]);
  workingVal = stateRegisters[3] + translateWord(workingWord, 32) + wordArray[8] +
               (abs(sin(sineTrack++)) * 4294967296);
  temp = workingVal % 4294967296;
  rotationalLeftShift(workingWord, temp, 11);
  workingVal = (stateRegisters[0] + translateWord(workingWord, 32)) % 4294967296;
  stateRegisters[3] = (uint32_t)workingVal;

  // C = D + rotationalLeftShift((C + parity(D, A, B) + blockWord[11] + abs(sin(35)) * 4294967296), 16)
  parity(workingWord, stateRegisters[3], stateRegisters[0], stateRegisters[1]);
  workingVal = stateRegisters[2] + translateWord(workingWord, 32) + wordArray[11] +
               (abs(sin(sineTrack++)) * 4294967296);
  temp = workingVal % 4294967296;
  rotationalLeftShift(workingWord, temp, 16);
  workingVal = (stateRegisters[3] + translateWord(workingWord, 32)) % 4294967296;
  stateRegisters[2] = (uint32_t)workingVal;

  // B = C + rotationalLeftShift((B + parity(C, D, A) + blockWord[14] + abs(sin(36)) * 4294967296), 23)
  parity(workingWord, stateRegisters[2], stateRegisters[3], stateRegisters[0]);
  workingVal = stateRegisters[1] + translateWord(workingWord, 32) + wordArray[14] +
               (abs(sin(sineTrack++)) * 4294967296);
  temp = workingVal % 4294967296;
  rotationalLeftShift(workingWord, temp, 23);
  workingVal = (stateRegisters[2] + translateWord(workingWord, 32)) % 4294967296;
  stateRegisters[1] = (uint32_t)workingVal;

  // A = B + rotationalLeftShift((A + parity(B, C, D) + blockWord[1] + abs(sin(37)) * 4294967296), 4)
  parity(workingWord, stateRegisters[1], stateRegisters[2], stateRegisters[3]);
  workingVal = stateRegisters[0] + translateWord(workingWord, 32) + wordArray[1] +
               (abs(sin(sineTrack++)) * 4294967296);
  temp = workingVal % 4294967296;
  rotationalLeftShift(workingWord, temp, 4);
  workingVal = (stateRegisters[1] + translateWord(workingWord, 32)) % 4294967296;
  stateRegisters[0] = (uint32_t)workingVal;

  // D = A + rotationalLeftShift((D + parity(A, B, C) + blockWord[4] + abs(sin(38)) * 4294967296), 11)
  parity(workingWord, stateRegisters[0], stateRegisters[1], stateRegisters[2]);
  workingVal = stateRegisters[3] + translateWord(workingWord, 32) + wordArray[4] +
               (abs(sin(sineTrack++)) * 4294967296);
  temp = workingVal % 4294967296;
  rotationalLeftShift(workingWord, temp, 11);
  workingVal = (stateRegisters[0] + translateWord(workingWord, 32)) % 4294967296;
  stateRegisters[3] = (uint32_t)workingVal;

  // C = D + rotationalLeftShift((C + parity(D, A, B) + blockWord[7] + abs(sin(39)) * 4294967296), 16)
  parity(workingWord, stateRegisters[3], stateRegisters[0], stateRegisters[1]);
  workingVal = stateRegisters[2] + translateWord(workingWord, 32) + wordArray[7] +
               (abs(sin(sineTrack++)) * 4294967296);
  temp = workingVal % 4294967296;
  rotationalLeftShift(workingWord, temp, 16);
  workingVal = (stateRegisters[3] + translateWord(workingWord, 32)) % 4294967296;
  stateRegisters[2] = (uint32_t)workingVal;

  // B = C + rotationalLeftShift((B + parity(C, D, A) + blockWord[10] + abs(sin(40)) * 4294967296), 23)
  parity(workingWord, stateRegisters[2], stateRegisters[3], stateRegisters[0]);
  workingVal = stateRegisters[1] + translateWord(workingWord, 32) + wordArray[10] +
               (abs(sin(sineTrack++)) * 4294967296);
  temp = workingVal % 4294967296;
  rotationalLeftShift(workingWord, temp, 23);
  workingVal = (stateRegisters[2] + translateWord(workingWord, 32)) % 4294967296;
  stateRegisters[1] = (uint32_t)workingVal;

  // A = B + rotationalLeftShift((A + parity(B, C, D) + blockWord[13] + abs(sin(41)) * 4294967296), 4)
  parity(workingWord, stateRegisters[1], stateRegisters[2], stateRegisters[3]);
  workingVal = stateRegisters[0] + translateWord(workingWord, 32) + wordArray[13] +
               (abs(sin(sineTrack++)) * 4294967296);
  temp = workingVal % 4294967296;
  rotationalLeftShift(workingWord, temp, 4);
  workingVal = (stateRegisters[1] + translateWord(workingWord, 32)) % 4294967296;
  stateRegisters[0] = (uint32_t)workingVal;

  // D = A + rotationalLeftShift((D + parity(A, B, C) + blockWord[0] + abs(sin(42)) * 4294967296), 11)
  parity(workingWord, stateRegisters[0], stateRegisters[1], stateRegisters[2]);
  workingVal = stateRegisters[3] + translateWord(workingWord, 32) + wordArray[0] +
               (abs(sin(sineTrack++)) * 4294967296);
  temp = workingVal % 4294967296;
  rotationalLeftShift(workingWord, temp, 11);
  workingVal = (stateRegisters[0] + translateWord(workingWord, 32)) % 4294967296;
  stateRegisters[3] = (uint32_t)workingVal;

  // C = D + rotationalLeftShift((C + parity(D, A, B) + blockWord[3] + abs(sin(43)) * 4294967296), 16)
  parity(workingWord, stateRegisters[3], stateRegisters[0], stateRegisters[1]);
  workingVal = stateRegisters[2] + translateWord(workingWord, 32) + wordArray[3] +
               (abs(sin(sineTrack++)) * 4294967296);
  temp = workingVal % 4294967296;
  rotationalLeftShift(workingWord, temp, 16);
  workingVal = (stateRegisters[3] + translateWord(workingWord, 32)) % 4294967296;
  stateRegisters[2] = (uint32_t)workingVal;

  // B = C + rotationalLeftShift((B + parity(C, D, A) + blockWord[6] + abs(sin(44)) * 4294967296), 23)
  parity(workingWord, stateRegisters[2], stateRegisters[3], stateRegisters[0]);
  workingVal = stateRegisters[1] + translateWord(workingWord, 32) + wordArray[6] +
               (abs(sin(sineTrack++)) * 4294967296);
  temp = workingVal % 4294967296;
  rotationalLeftShift(workingWord, temp, 23);
  workingVal = (stateRegisters[2] + translateWord(workingWord, 32)) % 4294967296;
  stateRegisters[1] = (uint32_t)workingVal;

  // A = B + rotationalLeftShift((A + parity(B, C, D) + blockWord[9] + abs(sin(45)) * 4294967296), 4)
  parity(workingWord, stateRegisters[1], stateRegisters[2], stateRegisters[3]);
  workingVal = stateRegisters[0] + translateWord(workingWord, 32) + wordArray[9] +
               (abs(sin(sineTrack++)) * 4294967296);
  temp = workingVal % 4294967296;
  rotationalLeftShift(workingWord, temp, 4);
  workingVal = (stateRegisters[1] + translateWord(workingWord, 32)) % 4294967296;
  stateRegisters[0] = (uint32_t)workingVal;

  // D = A + rotationalLeftShift((D + parity(A, B, C) + blockWord[12] + abs(sin(46)) * 4294967296), 11)
  parity(workingWord, stateRegisters[0], stateRegisters[1], stateRegisters[2]);
  workingVal = stateRegisters[3] + translateWord(workingWord, 32) + wordArray[12] +
               (abs(sin(sineTrack++)) * 4294967296);
  temp = workingVal % 4294967296;
  rotationalLeftShift(workingWord, temp, 11);
  workingVal = (stateRegisters[0] + translateWord(workingWord, 32)) % 4294967296;
  stateRegisters[3] = (uint32_t)workingVal;

  // C = D + rotationalLeftShift((C + parity(D, A, B) + blockWord[15] + abs(sin(47)) * 4294967296), 16)
  parity(workingWord, stateRegisters[3], stateRegisters[0], stateRegisters[1]);
  workingVal = stateRegisters[2] + translateWord(workingWord, 32) + wordArray[15] +
               (abs(sin(sineTrack++)) * 4294967296);
  temp = workingVal % 4294967296;
  rotationalLeftShift(workingWord, temp, 16);
  workingVal = (stateRegisters[3] + translateWord(workingWord, 32)) % 4294967296;
  stateRegisters[2] = (uint32_t)workingVal;

  // B = C + rotationalLeftShift((B + parity(C, D, A) + blockWord[2] + abs(sin(48)) * 4294967296), 23)
  parity(workingWord, stateRegisters[2], stateRegisters[3], stateRegisters[0]);
  workingVal = stateRegisters[1] + translateWord(workingWord, 32) + wordArray[2] +
               (abs(sin(sineTrack++)) * 4294967296);
  temp = workingVal % 4294967296;
  rotationalLeftShift(workingWord, temp, 23);
  workingVal = (stateRegisters[2] + translateWord(workingWord, 32)) % 4294967296;
  stateRegisters[1] = (uint32_t)workingVal;

  /* Round 3 Operations Finish */

  /* Round 4 Operations Start */

  // A = B + rotationalLeftShift((A + weirdChoice(B, C, D) + blockWord[0] + abs(sin(49)) * 4294967296), 6)
  weirdChoiceVariant(workingWord, stateRegisters[1], stateRegisters[2], stateRegisters[3]);
  workingVal = stateRegisters[0] + translateWord(workingWord, 32) + wordArray[0] +
               (abs(sin(sineTrack++)) * 4294967296);
  temp = workingVal % 4294967296;
  rotationalLeftShift(workingWord, temp, 6);
  workingVal = (stateRegisters[1] + translateWord(workingWord, 32)) % 4294967296;
  stateRegisters[0] = (uint32_t)workingVal;

  // D = A + rotationalLeftShift((D + weirdChoice(A, B, C) + blockWord[7] + abs(sin(50)) * 4294967296), 10)
  weirdChoiceVariant(workingWord, stateRegisters[0], stateRegisters[1], stateRegisters[2]);
  workingVal = stateRegisters[3] + translateWord(workingWord, 32) + wordArray[7] +
               (abs(sin(sineTrack++)) * 4294967296);
  temp = workingVal % 4294967296;
  rotationalLeftShift(workingWord, temp, 10);
  workingVal = (stateRegisters[0] + translateWord(workingWord, 32)) % 4294967296;
  stateRegisters[3] = (uint32_t)workingVal;

  // C = D + rotationalLeftShift((C + weirdChoice(D, A, B) + blockWord[14] + abs(sin(51)) * 4294967296), 15)
  weirdChoiceVariant(workingWord, stateRegisters[3], stateRegisters[0], stateRegisters[1]);
  workingVal = stateRegisters[2] + translateWord(workingWord, 32) + wordArray[14] +
               (abs(sin(sineTrack++)) * 4294967296);
  temp = workingVal % 4294967296;
  rotationalLeftShift(workingWord, temp, 15);
  workingVal = (stateRegisters[3] + translateWord(workingWord, 32)) % 4294967296;
  stateRegisters[2] = (uint32_t)workingVal;

  // B = C + rotationalLeftShift((B + weirdChoice(C, D, A) + blockWord[5] + abs(sin(52)) * 4294967296), 21)
  weirdChoiceVariant(workingWord, stateRegisters[2], stateRegisters[3], stateRegisters[0]);
  workingVal = stateRegisters[1] + translateWord(workingWord, 32) + wordArray[5] +
               (abs(sin(sineTrack++)) * 4294967296);
  temp = workingVal % 4294967296;
  rotationalLeftShift(workingWord, temp, 21);
  workingVal = (stateRegisters[2] + translateWord(workingWord, 32)) % 4294967296;
  stateRegisters[1] = (uint32_t)workingVal;

  // A = B + rotationalLeftShift((A + weirdChoice(B, C, D) + blockWord[12] + abs(sin(53)) * 4294967296), 6)
  weirdChoiceVariant(workingWord, stateRegisters[1], stateRegisters[2], stateRegisters[3]);
  workingVal = stateRegisters[0] + translateWord(workingWord, 32) + wordArray[12] +
               (abs(sin(sineTrack++)) * 4294967296);
  temp = workingVal % 4294967296;
  rotationalLeftShift(workingWord, temp, 6);
  workingVal = (stateRegisters[1] + translateWord(workingWord, 32)) % 4294967296;
  stateRegisters[0] = (uint32_t)workingVal;

  // D = A + rotationalLeftShift((D + weirdChoice(A, B, C) + blockWord[3] + abs(sin(54)) * 4294967296), 10)
  weirdChoiceVariant(workingWord, stateRegisters[0], stateRegisters[1], stateRegisters[2]);
  workingVal = stateRegisters[3] + translateWord(workingWord, 32) + wordArray[3] +
               (abs(sin(sineTrack++)) * 4294967296);
  temp = workingVal % 4294967296;
  rotationalLeftShift(workingWord, temp, 10);
  workingVal = (stateRegisters[0] + translateWord(workingWord, 32)) % 4294967296;
  stateRegisters[3] = (uint32_t)workingVal;

  // C = D + rotationalLeftShift((C + weirdChoice(D, A, B) + blockWord[10] + abs(sin(55)) * 4294967296), 15)
  weirdChoiceVariant(workingWord, stateRegisters[3], stateRegisters[0], stateRegisters[1]);
  workingVal = stateRegisters[2] + translateWord(workingWord, 32) + wordArray[10] +
               (abs(sin(sineTrack++)) * 4294967296);
  temp = workingVal % 4294967296;
  rotationalLeftShift(workingWord, temp, 15);
  workingVal = (stateRegisters[3] + translateWord(workingWord, 32)) % 4294967296;
  stateRegisters[2] = (uint32_t)workingVal;

  // B = C + rotationalLeftShift((B + weirdChoice(C, D, A) + blockWord[1] + abs(sin(56)) * 4294967296), 21)
  weirdChoiceVariant(workingWord, stateRegisters[2], stateRegisters[3], stateRegisters[0]);
  workingVal = stateRegisters[1] + translateWord(workingWord, 32) + wordArray[1] +
               (abs(sin(sineTrack++)) * 4294967296);
  temp = workingVal % 4294967296;
  rotationalLeftShift(workingWord, temp, 21);
  workingVal = (stateRegisters[2] + translateWord(workingWord, 32)) % 4294967296;
  stateRegisters[1] = (uint32_t)workingVal;

  // A = B + rotationalLeftShift((A + weirdChoice(B, C, D) + blockWord[8] + abs(sin(57)) * 4294967296), 6)
  weirdChoiceVariant(workingWord, stateRegisters[1], stateRegisters[2], stateRegisters[3]);
  workingVal = stateRegisters[0] + translateWord(workingWord, 32) + wordArray[8] +
               (abs(sin(sineTrack++)) * 4294967296);
  temp = workingVal % 4294967296;
  rotationalLeftShift(workingWord, temp, 6);
  workingVal = (stateRegisters[1] + translateWord(workingWord, 32)) % 4294967296;
  stateRegisters[0] = (uint32_t)workingVal;

  // D = A + rotationalLeftShift((D + weirdChoice(A, B, C) + blockWord[15] + abs(sin(58)) * 4294967296), 10)
  weirdChoiceVariant(workingWord, stateRegisters[0], stateRegisters[1], stateRegisters[2]);
  workingVal = stateRegisters[3] + translateWord(workingWord, 32) + wordArray[15] +
               (abs(sin(sineTrack++)) * 4294967296);
  temp = workingVal % 4294967296;
  rotationalLeftShift(workingWord, temp, 10);
  workingVal = (stateRegisters[0] + translateWord(workingWord, 32)) % 4294967296;
  stateRegisters[3] = (uint32_t)workingVal;

  // C = D + rotationalLeftShift((C + weirdChoice(D, A, B) + blockWord[6] + abs(sin(59)) * 4294967296), 15)
  weirdChoiceVariant(workingWord, stateRegisters[3], stateRegisters[0], stateRegisters[1]);
  workingVal = stateRegisters[2] + translateWord(workingWord, 32) + wordArray[6] +
               (abs(sin(sineTrack++)) * 4294967296);
  temp = workingVal % 4294967296;
  rotationalLeftShift(workingWord, temp, 15);
  workingVal = (stateRegisters[3] + translateWord(workingWord, 32)) % 4294967296;
  stateRegisters[2] = (uint32_t)workingVal;

  // B = C + rotationalLeftShift((B + weirdChoice(C, D, A) + blockWord[13] + abs(sin(60)) * 4294967296), 21)
  weirdChoiceVariant(workingWord, stateRegisters[2], stateRegisters[3], stateRegisters[0]);
  workingVal = stateRegisters[1] + translateWord(workingWord, 32) + wordArray[13] +
               (abs(sin(sineTrack++)) * 4294967296);
  temp = workingVal % 4294967296;
  rotationalLeftShift(workingWord, temp, 21);
  workingVal = (stateRegisters[2] + translateWord(workingWord, 32)) % 4294967296;
  stateRegisters[1] = (uint32_t)workingVal;

  // A = B + rotationalLeftShift((A + weirdChoice(B, C, D) + blockWord[4] + abs(sin(61)) * 4294967296), 6)
  weirdChoiceVariant(workingWord, stateRegisters[1], stateRegisters[2], stateRegisters[3]);
  workingVal = stateRegisters[0] + translateWord(workingWord, 32) + wordArray[4] +
               (abs(sin(sineTrack++)) * 4294967296);
  temp = workingVal % 4294967296;
  rotationalLeftShift(workingWord, temp, 6);
  workingVal = (stateRegisters[1] + translateWord(workingWord, 32)) % 4294967296;
  stateRegisters[0] = (uint32_t)workingVal;

  // D = A + rotationalLeftShift((D + weirdChoice(A, B, C) + blockWord[11]] + abs(sin(62)) * 4294967296), 10)
  weirdChoiceVariant(workingWord, stateRegisters[0], stateRegisters[1], stateRegisters[2]);
  workingVal = stateRegisters[3] + translateWord(workingWord, 32) + wordArray[11] +
               (abs(sin(sineTrack++)) * 4294967296);
  temp = workingVal % 4294967296;
  rotationalLeftShift(workingWord, temp, 10);
  workingVal = (stateRegisters[0] + translateWord(workingWord, 32)) % 4294967296;
  stateRegisters[3] = (uint32_t)workingVal;

  // C = D + rotationalLeftShift((C + weirdChoice(D, A, B) + blockWord[2] + abs(sin(63)) * 4294967296), 15)
  weirdChoiceVariant(workingWord, stateRegisters[3], stateRegisters[0], stateRegisters[1]);
  workingVal = stateRegisters[2] + translateWord(workingWord, 32) + wordArray[2] +
               (abs(sin(sineTrack++)) * 4294967296);
  temp = workingVal % 4294967296;
  rotationalLeftShift(workingWord, temp, 15);
  workingVal = (stateRegisters[3] + translateWord(workingWord, 32)) % 4294967296;
  stateRegisters[2] = (uint32_t)workingVal;

  // B = C + rotationalLeftShift((B + weirdChoice(C, D, A) + blockWord[9] + abs(sin(64)) * 4294967296), 21)
  weirdChoiceVariant(workingWord, stateRegisters[2], stateRegisters[3], stateRegisters[0]);
  workingVal = stateRegisters[1] + translateWord(workingWord, 32) + wordArray[9] +
               (abs(sin(sineTrack++)) * 4294967296);
  temp = workingVal % 4294967296;
  rotationalLeftShift(workingWord, temp, 21);
  workingVal = (stateRegisters[2] + translateWord(workingWord, 32)) % 4294967296;
  stateRegisters[1] = (uint32_t)workingVal;

  /* Round 4 Operations Finish */
}

string md5(string data) {
  // Calculate the amount of bits needed to fill pad buffer
  unsigned long padLength = data.length() * 8; // Each character in the data is 8
                                               // bits
  unsigned long lengthHolder = padLength; // Saved for later to add to the end
                                          // of the pad buffer

  // Calculates the exact size the pad buffer needs to be to fit all the bits
  padLength = (512 * (padLength / 512 + 1));

  if(lengthHolder + 1 > padLength - 64)
    padLength += 512;

  // Create array to represent the pad buffer of bits
  bool padBuffer[padLength];

  // Zero out pad buffer
  for(int fill = 0; fill < padLength; ++fill)
    padBuffer[fill] = 0;

  /* Fill pad buffer */
  // Fill with bits taken from every byte of the given data
  int padPos = 0;
  for(int dataPos = 0; dataPos < data.length(); ++dataPos) {
    uint8_t dataVal = data.at(dataPos);

    for(int bitPos = 7; bitPos >= 0; --bitPos) {
      padBuffer[padPos] = dataVal & (1l << bitPos);
      ++padPos;
    }
  }

  // Add a 1 bit
  padBuffer[padPos] = 1;

  padPos = padLength - 64;

  // Fill pad with 0s until 64 bits of space remain:
  // This is already done after we initialize the array
  // since we zero it out to get rid of any garbage left
  // in memory

  // Create a byte array using the individual bytes of the saved message length
  // before padding, using little endian convention
  uint64_t val = lengthHolder;

  uint8_t byteArray[8] = {0, 0, 0, 0, 0, 0, 0, 0};

  for(short byte = 0; byte < 8; ++byte)
    switch(byte) {
      case 0:
        byteArray[byte] = (lengthHolder >> 0) & 255;
        break;

      case 1:
        byteArray[byte] = (lengthHolder >> 8) & 255;
        break;

      case 2:
        byteArray[byte] = (lengthHolder >> 16) & 255;
        break;

      case 3:
        byteArray[byte] = (lengthHolder >> 24) & 255;
        break;

      case 4:
        byteArray[byte] = (lengthHolder >> 32) & 255;
        break;

      case 5:
        byteArray[byte] = (lengthHolder >> 40) & 255;
        break;

      case 6:
        byteArray[byte] = (lengthHolder >> 48) & 255;
        break;

      case 7:
        byteArray[byte] = (lengthHolder >> 56) & 255;
    }

  // Append byte array into the remaining space of the pad buffer as individual
  // bits
  for(uint8_t val: byteArray)
    for(short bitPos = 7; bitPos >= 0; --bitPos) {
      bool bit = val & (1l << bitPos);

      padBuffer[padPos++] = bit;
    }

  // Create and fill initial state registers
  uint32_t registers[4];

  for(short count = 0; count < 4; ++count)
    switch(count) {
      case 0:
        registers[count] = 1732584193;  // 0x67452301
        break;

      case 1:
        registers[count] = 4023233417;  // 0xefcdab89
        break;

      case 2:
        registers[count] = 2562383102;  // 0x98badcfe
        break;

      case 3:
        registers[count] = 271733878;   // 0x10325476
    }

  // Process pad buffer in 512 bit blocks
  bool block[512];

  int blockTrack = 0;
  uint32_t registerStateSave[4];

  for(int bitCount = 0; bitCount < padLength; ++bitCount) {
    block[blockTrack] = padBuffer[bitCount];
    ++blockTrack;

    if(blockTrack == 512) {
      // Save the state of the current registers
      short pos = 0;
      for (uint32_t val: registers)
        registerStateSave[pos++] = val;

      md5processBlock(block, registers);

      // Add saved register state to the newly processed register state to
      // obtain the final resulting register state of the current iteration
      unsigned long tempVal = 0;
      for(short pointer = 0; pointer < 4; ++pointer) {
        for(short bitPos = 31; bitPos >= 0; --bitPos) {
          if(registers[pointer] & (1l << bitPos))
            tempVal += 1l << bitPos;

          if(registerStateSave[pointer] & (1l << bitPos))
            tempVal += 1l << bitPos;
        }

        uint32_t newStateVal = tempVal % 4294967296;

        registers[pointer] = newStateVal;

        tempVal = 0;
      }

      blockTrack = 0;
    }
  }

  // Translate final register state values into an array of bytes, arranged in
  // little endian convention
  uint8_t digestArray[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

  short byteTracker = 0;
  for(uint32_t registerVal: registers) {
    digestArray[byteTracker++] = (registerVal >> 0) & 255;
    digestArray[byteTracker++] = (registerVal >> 8) & 255;
    digestArray[byteTracker++] = (registerVal >> 16) & 255;
    digestArray[byteTracker++] = (registerVal >> 24) & 255;
  }

  return hexDigest(digestArray, 16);
}

/*---------------------------------------------------------------------------*/
/*                            Begin SHA0 Section                             */
/*---------------------------------------------------------------------------*/

/*
  SHA0 Algorithm designed using the specifications described in

  NIST FIPS Pub 180

  Published in May 1993
*/

// Schedule generation function used by SHA0
void generateScheduleSHA0(bool block[512], uint32_t schedule[80]) {
  // Create the first 16 32-bit words using the message block
  short bitCount = 0;
  short schedulePos = 0;
  short bitPos = 31;
  bool word[32];
  for(int blockCount = 0; blockCount < 512; ++blockCount) {
    word[bitCount] = block[blockCount];
    ++bitCount;

    if(bitCount == 32) {
      uint32_t val = 0;

      for (bool wordBit: word) {
        if (wordBit)
          val += 1 << bitPos;
        --bitPos;
      }

      schedule[schedulePos] = val;
      ++schedulePos;

      bitCount = 0;
      bitPos = 31;
    }
  }

  // Expand the schedule to 80 32-bit words
  uint32_t val1, val2, val3, val4;
  uint32_t result;
  while(schedulePos < 80) {
    val1 = schedule[schedulePos - 3];
    val2 = schedule[schedulePos - 8];
    val3 = schedule[schedulePos - 14];
    val4 = schedule[schedulePos - 16];

    result = val1 ^ val2 ^ val3 ^ val4;
    schedule[schedulePos++] = result;
  }
}

void sha0processBlock(bool block[512], uint32_t registers[5], uint32_t constants[80]) {
  /* Create message schedule */
  uint32_t schedule[80];

  generateScheduleSHA0(block, schedule);

  /* Begin compression process */
  for(short round = 0; round < 80; ++round) {
    uint32_t scheduleWord = schedule[round];
    uint32_t constantWord = constants[round];

    /* Create temporary 32-bit word used to help change the state registers */

    // Create first temp word by passing the value in the first register to the
    // rotational left shift function with a shift value of 5
    bool tempWord1[32];
    rotationalLeftShift(tempWord1, registers[0], 5);

    // Create second temp word by passing the values in registers 2, 3 and 4 to
    // the proper function based on the current round
    bool tempWord2[32];
    if(round < 20)
      oldChoice(tempWord2, registers[1], registers[2], registers[3]);
    else if((round >= 20 && round < 40) || (round >= 60))
      parity(tempWord2, registers[1], registers[2], registers[3]);
    else
      oldMajority(tempWord2, registers[1], registers[2], registers[3]);

    // Temp word 3 is simply the 5th register, temp word 4 is the schedule word,
    // temp word 5 is the constant word
    uint32_t val = registers[4];
    bool tempWord3[32];
    bool tempWord4[32];
    bool tempWord5[32];
    short wordPos = 0;
    for(short bitPos = 31; bitPos >= 0; --bitPos) {
      tempWord3[bitPos] = val & (1l << wordPos);
      tempWord4[bitPos] = scheduleWord & (1l << wordPos);
      tempWord5[bitPos] = constantWord & (1l << wordPos);

      ++wordPos;
    }

    // Add all words up taken at module 2^32 to get the final temp word
    unsigned long finalTempVal = 0;

    int bitTrack = 0;
    for(short bitPos = 31; bitPos >= 0; --bitPos) {
      if(tempWord1[bitPos])
        finalTempVal += 1l << bitTrack;

      if(tempWord2[bitPos])
        finalTempVal += 1l << bitTrack;

      if(tempWord3[bitPos])
        finalTempVal += 1l << bitTrack;

      if(tempWord4[bitPos])
        finalTempVal += 1l << bitTrack;

      if(tempWord5[bitPos])
        finalTempVal += 1l << bitTrack;

      ++bitTrack;
    }

    uint32_t finalVal = finalTempVal % 4294967296;

    /* Update state registers */

    // Shift all register values to the right, discarding the value held in
    // register 5. Third register is replaced by the value of register 2
    // with a rotational left shift of 30 performed on it.
    for(int iter = 4; iter > 0; --iter)
      if(iter == 2) {
        bool tempWord[32];
        rotationalLeftShift(tempWord, registers[iter - 1], 30);

        uint32_t val = 0;
        short bitPos = 31;
        for(bool bit: tempWord) {
          if(bit)
            val += 1l << bitPos;
          --bitPos;
        }

        registers[iter] = val;
      } else
        registers[iter] = registers[iter - 1];

    // Replace the value in the first register with our generated temporary
    // value
    registers[0] = finalVal;
  }
}

string sha0(string data) {
  // Calculate the amount of bits needed to fill pad buffer
  unsigned long padLength = data.length() * 8; // Each character in the data is 8
                                               // bits
  unsigned long lengthHolder = padLength; // Saved for later to add to the end
                                          // of the pad buffer

  // Calculates the exact size the pad buffer needs to be to fit all the bits
  padLength = (512 * (padLength / 512 + 1));

  if(lengthHolder + 1 > padLength - 64)
    padLength += 512;

  // Create array to represent the pad buffer of bits
  bool padBuffer[padLength];

  // Zero out pad buffer
  for(int fill = 0; fill < padLength; ++fill)
    padBuffer[fill] = 0;

  /* Fill pad buffer */
  // Fill with bits taken from every byte of the given data
  int padPos = 0;
  for(int dataPos = 0; dataPos < data.length(); ++dataPos) {
    uint8_t dataVal = data.at(dataPos);

    for(int bitPos = 7; bitPos >= 0; --bitPos) {
      padBuffer[padPos] = dataVal & (1l << bitPos);
      ++padPos;
    }
  }

  // Add a 1 bit
  padBuffer[padPos] = 1;

  // Fill pad with 0s until 64 bits of space remain:
  // This is already done after we initialize the array
  // since we zero it out to get rid of any garbage left
  // in memory

  padPos = padLength - 1;

  uint64_t val = lengthHolder;
  uint64_t temp = 0;

  // This makes sure that only the bits representing the bit size
  // of the data is accurately inserted into pad buffer
  for(int bitPos = 0; bitPos <= 63; ++bitPos) {
    bool bit = val & (1l << bitPos);

    padBuffer[padPos] = bit;

    if(bit) {
      temp += 1l << bitPos;
      if(temp == val)
        break;
    }

    --padPos;
  }

  // Create constants array and initial state registers
  uint32_t constants[80];
  uint32_t stateRegisters[5];

  // Fill constants array
  for(short count = 0; count < 80; ++count)
    if(count < 20)
      constants[count] = 1518500249;    // 0x5a827999
    else if(count >= 20 && count < 40)
      constants[count] = 1859775393;    // 0x6ed9eba1
    else if(count >= 30 && count < 60)
      constants[count] = 2400959708;    // 0x8f1bbcdc
    else
      constants[count] = 3395469782;    // 0xca62c1d6

  // Fill initial state registers
  for(short count = 0; count < 5; ++count)
    switch(count) {
      case 0:
        stateRegisters[count] = 1732584193;  // 0x67452301
        break;

      case 1:
        stateRegisters[count] = 4023233417;  // 0xefcdab89
        break;

      case 2:
        stateRegisters[count] = 2562383102;  // 0x98badcfe
        break;

      case 3:
        stateRegisters[count] = 271733878;   // 0x10325476
        break;

      case 4:
        stateRegisters[count] = 3285377520;  // 0xc3d2e1f0
    }

  // Process pad buffer in 512 bit blocks
  bool block[512];

  int blockTrack = 0;
  uint32_t registerStateSave[5];

  for(int bitCount = 0; bitCount < padLength; ++bitCount) {
    block[blockTrack] = padBuffer[bitCount];
    ++blockTrack;

    if(blockTrack == 512) {
      // Save the state of the current registers
      short pos = 0;
      for (uint32_t val: stateRegisters)
        registerStateSave[pos++] = val;

      sha0processBlock(block, stateRegisters, constants);

      // Add saved register state to the newly processed register state to
      // obtain the final resulting register state of the current iteration
      unsigned long tempVal = 0;
      for(short pointer = 0; pointer < 5; ++pointer) {
        for(short bitPos = 31; bitPos >= 0; --bitPos) {
          if(stateRegisters[pointer] & (1l << bitPos))
            tempVal += 1l << bitPos;

          if(registerStateSave[pointer] & (1l << bitPos))
            tempVal += 1l << bitPos;
        }

        uint32_t newStateVal = tempVal % 4294967296;

        stateRegisters[pointer] = newStateVal;

        tempVal = 0;
      }

      blockTrack = 0;
    }
  }

  return hexDigest(stateRegisters, 5);
}

/*---------------------------------------------------------------------------*/
/*                            Begin SHA1 Section                             */
/*---------------------------------------------------------------------------*/

/*
  SHA1 Algorithm designed using the specifications described in

  NIST FIPS Publication 180-4

  published in August 2015
*/

void generateScheduleSHA1(bool block[512], uint32_t schedule[80]) {
  // Create the first 16 32-bit words using the message block
  short bitCount = 0;
  short schedulePos = 0;
  short bitPos = 31;
  bool word[32];
  for(int blockCount = 0; blockCount < 512; ++blockCount) {
    word[bitCount] = block[blockCount];
    ++bitCount;

    if(bitCount == 32) {
      uint32_t val = 0;

      for (bool wordBit: word) {
        if (wordBit)
            val += 1 << bitPos;
        --bitPos;
      }

      schedule[schedulePos] = val;
      ++schedulePos;

      bitCount = 0;
      bitPos = 31;
    }
  }

  // Expand the schedule to 80 32-bit words
  uint32_t val1, val2, val3, val4;
  uint32_t result;
  while(schedulePos < 80) {
    val1 = schedule[schedulePos - 3];
    val2 = schedule[schedulePos - 8];
    val3 = schedule[schedulePos - 14];
    val4 = schedule[schedulePos - 16];

    result = val1 ^ val2 ^ val3 ^ val4;

    bool scheduleWord[32];
    rotationalLeftShift(scheduleWord, result, 1);

    result = 0;
    short bitPos = 31;
    for(bool bit: scheduleWord) {
      if(bit)
        result += 1 << bitPos;
      --bitPos;
    }

    schedule[schedulePos++] = result;
  }
}

void sha1processBlock(bool block[512], uint32_t registers[5], uint32_t constants[80]) {
  /* Generate message schedule */

  uint32_t schedule[80];

  generateScheduleSHA1(block, schedule);

  /* Begin compression process */
  for(short round = 0; round < 80; ++round) {
    uint32_t scheduleWord = schedule[round];
    uint32_t constantWord = constants[round];

    /* Create temporary 32-bit word used to help change the state registers */

    // Create first temp word by passing the value in the first register to the
    // rotational left shift function with a shift value of 5
    bool tempWord1[32];
    rotationalLeftShift(tempWord1, registers[0], 5);

    // Create second temp word by passing the values in registers 2, 3 and 4 to
    // the proper function based on the current round
    bool tempWord2[32];
    if(round < 20)
      choice(tempWord2, registers[1], registers[2], registers[3]);
    else if((round >= 20 && round < 40) || (round >= 60))
      parity(tempWord2, registers[1], registers[2], registers[3]);
    else
      majority(tempWord2, registers[1], registers[2], registers[3]);

    // Temp word 3 is simply the 5th register, temp word 4 is the schedule word,
    // temp word 5 is the constant word
    uint32_t val = registers[4];
    bool tempWord3[32];
    bool tempWord4[32];
    bool tempWord5[32];
    short wordPos = 0;
    for(short bitPos = 31; bitPos >= 0; --bitPos) {
      tempWord3[bitPos] = val & (1l << wordPos);
      tempWord4[bitPos] = scheduleWord & (1l << wordPos);
      tempWord5[bitPos] = constantWord & (1l << wordPos);

      ++wordPos;
    }

    // Add all words up taken at module 2^32 to get the final temp word
    unsigned long finalTempVal = 0;

    int bitTrack = 0;
    for(short bitPos = 31; bitPos >= 0; --bitPos) {
      if(tempWord1[bitPos])
        finalTempVal += 1l << bitTrack;

      if(tempWord2[bitPos])
        finalTempVal += 1l << bitTrack;

      if(tempWord3[bitPos])
        finalTempVal += 1l << bitTrack;

      if(tempWord4[bitPos])
        finalTempVal += 1l << bitTrack;

      if(tempWord5[bitPos])
        finalTempVal += 1l << bitTrack;

      ++bitTrack;
    }

    uint32_t finalVal = finalTempVal % 4294967296;

    /* Update state registers */

    // Shift all register values to the right, discarding the value held in
    // register 5. Third register is replaced by the value of register 2
    // with a rotational left shift of 30 performed on it.
    for(int iter = 4; iter > 0; --iter)
      if(iter == 2) {
        bool tempWord[32];
        rotationalLeftShift(tempWord, registers[iter - 1], 30);

        uint32_t val = 0;
        short bitPos = 31;
        for(bool bit: tempWord) {
          if(bit)
            val += 1l << bitPos;
          --bitPos;
        }

        registers[iter] = val;
      } else
        registers[iter] = registers[iter - 1];

    // Replace the value in the first register with our generated temporary
    // value
    registers[0] = finalVal;
  }
}

string sha1(string data) {
  // Calculate the amount of bits needed to fill pad buffer
  unsigned long padLength = data.length() * 8; // Each character in the data is 8
                                               // bits
  unsigned long lengthHolder = padLength; // Saved for later to add to the end
  // of the pad buffer

  // Calculates the exact size the pad buffer needs to be to fit all the bits
  padLength = (512 * (padLength / 512 + 1));

  if(lengthHolder + 1 > padLength - 64)
    padLength += 512;

  // Create array to represent the pad buffer of bits
  bool padBuffer[padLength];

  // Zero out pad buffer
  for(int fill = 0; fill < padLength; ++fill)
    padBuffer[fill] = 0;

  /* Fill pad buffer */

  // Fill with bits taken from every byte of the given data
  int padPos = 0;
  for(int dataPos = 0; dataPos < data.length(); ++dataPos) {
    uint8_t dataVal = data.at(dataPos);

    for(int bitPos = 7; bitPos >= 0; --bitPos) {
      padBuffer[padPos] = dataVal & (1l << bitPos);
      ++padPos;
    }
  }

  // Add a 1 bit
  padBuffer[padPos] = 1;

  // Fill pad with 0s until 64 bits of space remain:
  // This is already done after we initialize the array
  // since we zero it out to get rid of any garbage left
  // in memory

  padPos = padLength - 1;

  uint64_t val = lengthHolder;
  uint64_t temp = 0;

  // This makes sure that only the bits representing the bit size
  // of the data is accurately inserted into pad buffer
  for(int bitPos = 0; bitPos <= 63; ++bitPos) {
    bool bit = val & (1l << bitPos);

    padBuffer[padPos] = bit;

    if(bit) {
      temp += 1l << bitPos;
      if(temp == val)
        break;
    }

    --padPos;
  }

  // Create constants array and initial state registers
  uint32_t constants[80];
  uint32_t stateRegisters[5];

  // Fill constants array
  for(short count = 0; count < 80; ++count)
    if(count < 20)
      constants[count] = 1518500249;    // 0x5a827999
    else if(count >= 20 && count < 40)
      constants[count] = 1859775393;    // 0x6ed9eba1
    else if(count >= 30 && count < 60)
      constants[count] = 2400959708;    // 0x8f1bbcdc
    else
      constants[count] = 3395469782;    // 0xca62c1d6

  // Fill initial state registers
  for(short count = 0; count < 5; ++count)
    switch(count) {
      case 0:
        stateRegisters[count] = 1732584193;  // 0x67452301
        break;

      case 1:
        stateRegisters[count] = 4023233417;  // 0xefcdab89
        break;

      case 2:
        stateRegisters[count] = 2562383102;  // 0x98badcfe
        break;

      case 3:
        stateRegisters[count] = 271733878;   // 0x10325476
        break;

      case 4:
        stateRegisters[count] = 3285377520;  // 0xc3d2e1f0
    }

  // Process pad buffer in 512 bit blocks
  bool block[512];

  int blockTrack = 0;
  uint32_t registerStateSave[5];

  for(int bitCount = 0; bitCount < padLength; ++bitCount) {
    block[blockTrack] = padBuffer[bitCount];
    ++blockTrack;

    if(blockTrack == 512) {
      // Save the state of the current registers
      short pos = 0;
      for (uint32_t val: stateRegisters)
        registerStateSave[pos++] = val;

      sha1processBlock(block, stateRegisters, constants);

      // Add saved register state to the newly processed register state to
      // obtain the final resulting register state of the current iteration
      unsigned long tempVal = 0;
      for(short pointer = 0; pointer < 5; ++pointer) {
        for(short bitPos = 31; bitPos >= 0; --bitPos) {
          if(stateRegisters[pointer] & (1l << bitPos))
            tempVal += 1l << bitPos;

          if(registerStateSave[pointer] & (1l << bitPos))
            tempVal += 1l << bitPos;
        }

        uint32_t newStateVal = tempVal % 4294967296;

        stateRegisters[pointer] = newStateVal;

        tempVal = 0;
      }

      blockTrack = 0;
    }
  }

  return hexDigest(stateRegisters, 5);
}

/*---------------------------------------------------------------------------*/
/*                           Begin SHA256 Section                            */
/*---------------------------------------------------------------------------*/

/*
  SHA256 Algorithm designed using the specifications described in

  NIST FIPS Publication 180-4

  published in August 2015
*/

/*
  The lower sigma 0 (σ0) function for SHA224 and SHA256, defined as follows:

  Given a 32 bit number, create another 32 bit number by performing the following

  Rotational Right Shift of 7 bits from the original number XORd with
  Rotational Right Shift of 18 bits from the original number XORd with
  Right Shift of 3 bits from the original number
*/
void lowerSigma0_256(bool word[32], uint32_t val) {
  // Temp word 1 is the resulting word from performing a rotational right
  // shift on originally passed word 7 times
  bool tempWord1[32];
  rotationalRightShift(tempWord1, val, 7);

  // Temp word 2 is the resulting word from performing a rotational right
  // shift on originally passed word 18 times
  bool tempWord2[32];
  rotationalRightShift(tempWord2, val, 18);

  // Temp word 3 is the result of a right shift of 3
  bool tempWord3[32];
  uint32_t tempVal = val >> 3;
  short wordPos = 0;
  for(short bitPos = 31; bitPos >= 0; --bitPos) {
    bool bit = tempVal & (1l << bitPos);

    tempWord3[wordPos++] = bit;
  }

  // Resulting word comes from XORing all 3 generated temporary words
  for(short bitPos = 0; bitPos < 32; ++bitPos)
    word[bitPos] = tempWord1[bitPos] ^ tempWord2[bitPos] ^ tempWord3[bitPos];
}

/*
  The lower sigma 1 (σ1) function for SHA224 and SHA256, defined as follows:

  Given a 32 bit number, create another 32 bit number by performing the following

  Rotational Right Shift of 17 bits from the original number XORd with
  Rotational Right Shift of 19 bits from the original number XORd with
  Right Shift of 10 bits from the original number
*/
void lowerSigma1_256(bool word[32], uint32_t val) {\
  // Temp word 1 is the resulting word from performing a rotational right
  // shift on originally passed word 17 times
  bool tempWord1[32];
  rotationalRightShift(tempWord1, val, 17);

  // Temp word 2 is the resulting word from performing a rotational right
  // shift on originally passed word 19 times
  bool tempWord2[32];
  rotationalRightShift(tempWord2, val, 19);

  // Temp word 3 is the result of a right shift of 10
  bool tempWord3[32];
  uint32_t tempVal = val >> 10;
  short wordPos = 0;
  for(short bitPos = 31; bitPos >= 0; --bitPos) {
    bool bit = tempVal & (1l << bitPos);

    tempWord3[wordPos++] = bit;
  }

  // Resulting word comes from XORing all 3 generated temporary words
  for(short bitPos = 0; bitPos < 32; ++bitPos)
    word[bitPos] = tempWord1[bitPos] ^ tempWord2[bitPos] ^ tempWord3[bitPos];
}

/*
  The upper sigma 0 (Σ0) function for SHA224 and SHA256, defined as follows:

  Given a 32 bit number, create another 32 bit number by performing the following

  Rotational Right Shift of 2 bits from the original number XORd with
  Rotational Right Shift of 13 bits from the original number XORd with
  Rotational Right Shift of 22 bits from the original number
*/
void upperSigma0_256(bool word[32], uint32_t val) {
  // Temp word 1 is the resulting word from performing a rotational right
  // shift on originally passed word 2 times
  bool tempWord1[32];
  rotationalRightShift(tempWord1, val, 2);

  // Temp word 2 is the resulting word from performing a rotational right
  // shift on originally passed word 13 times
  bool tempWord2[32];
  rotationalRightShift(tempWord2, val, 13);

  // Temp word 3 is the resulting word from performing a rotational right
  // shift on originally passed word 22 times
  bool tempWord3[32];
  rotationalRightShift(tempWord3, val, 22);

  // Resulting word comes from XORing all 3 generated temporary words
  for(short bitPos = 0; bitPos < 32; ++bitPos)
    word[bitPos] = tempWord1[bitPos] ^ tempWord2[bitPos] ^ tempWord3[bitPos];
}

/*
  The upper sigma 1 (Σ1) function for SHA224 and SHA256, defined as follows:

  Given a 32 bit number, create another 32 bit number by performing the following

  Rotational Right Shift of 6 bits from the original number XORd with
  Rotational Right Shift of 11 bits from the original number XORd with
  Rotational Right Shift of 25 bits from the original number
*/
void upperSigma1_256(bool word[32], uint32_t val) {
  // Temp word 1 is the resulting word from performing a rotational right
  // shift on originally passed word 6 times
  bool tempWord1[32];
  rotationalRightShift(tempWord1, val, 6);

  // Temp word 2 is the resulting word from performing a rotational right
  // shift on originally passed word 11 times
  bool tempWord2[32];
  rotationalRightShift(tempWord2, val, 11);

  // Temp word 3 is the resulting word from performing a rotational right
  // shift on originally passed word 25 times
  bool tempWord3[32];
  rotationalRightShift(tempWord3, val, 25);

  // Resulting word comes from XORing all 3 generated temporary words
  for(short bitPos = 0; bitPos < 32; ++bitPos)
    word[bitPos] = tempWord1[bitPos] ^ tempWord2[bitPos] ^ tempWord3[bitPos];
}

// Message schedule generation function used by SHA224 and SHA256
void generateSchedule256(bool block[512], uint32_t schedule[64]) {
  // Create the first 16 32-bit words using the message block
  short bitCount = 0;
  short schedulePos = 0;
  short bitPos = 31;
  bool word[32];
  for(int blockCount = 0; blockCount < 512; ++blockCount) {
    word[bitCount] = block[blockCount];
    ++bitCount;

    if(bitCount == 32) {
      uint32_t val = 0;

      for (bool wordBit: word) {
        if (wordBit)
          val += 1 << bitPos;
        --bitPos;
      }

      schedule[schedulePos] = val;
      ++schedulePos;

      bitCount = 0;
      bitPos = 31;
    }
  }

  // Expand the schedule to 64 32-bit words
  while(schedulePos < 64) {
    bool word1[32];
    lowerSigma0_256(word1, schedule[schedulePos - 15]);

    bool word2[32];
    lowerSigma1_256(word2, schedule[schedulePos - 2]);

    short wordPos = 0;
    bool word3[32];
    uint32_t val = schedule[schedulePos - 7];
    while (bitPos >= 0) {
      word3[wordPos] = val & (1l << bitPos);
      ++wordPos;
      --bitPos;
    }

    bitPos = 31;
    wordPos = 0;
    bool word4[32];
    val = schedule[schedulePos - 16];
    while (bitPos >= 0) {
      word4[wordPos] = val & (1l << bitPos);
      ++wordPos;
      --bitPos;
    }

    bitPos = 31;

    // Add them all and take the result mod 2^32
    unsigned long tempValue = 0;
    short bitTrack = 0;
    for (short bitPos = 31; bitPos >= 0; --bitPos) {
      if (word1[bitPos])
        tempValue += 1l << bitTrack;

      if(word2[bitPos])
        tempValue += 1l << bitTrack;

      if(word3[bitPos])
        tempValue += 1l << bitTrack;

      if(word4[bitPos])
        tempValue += 1l << bitTrack;

      ++bitTrack;
    }

    uint32_t scheduleWord = tempValue % 4294967296;

    schedule[schedulePos] = scheduleWord;
    ++schedulePos;
  }
}

void generateStartingHashState256(uint32_t constArray[64], uint32_t registers[8]) {
  union {
    double input;
    uint64_t output;
  } data;

  // Generates the first 64 primes and uses the fractional bits of the cube
  // roots of these primes to create our constants and the fractional portion
  // of their square roots for the starting states of the registers

  // Calculate cube root of 2 and retrieve the constant
  data.input = cbrt(2.0);

  bitset<sizeof(double) * CHAR_BIT> bits(data.output);

  uint32_t val = 0;
  int pos = 31;
  for(int bitPos = 51; bitPos > 19; --bitPos) {
    if (bits[bitPos] == 1)
      val += 1l << pos;

    --pos;
  }

  constArray[0] = val;

  // Calculate square root of 2 and retrieve register 0
  data.input = sqrt(2.0);

  bitset<sizeof(double) * CHAR_BIT> bits2(data.output);

  val = 0;
  pos = 31;
  for(int bitPos = 51; bitPos > 19; --bitPos) {
    if (bits2[bitPos] == 1)
      val += 1l << pos;

    --pos;
  }

  registers[0] = val;

  // Calculate the remaining 63 primes and their resulting constants and
  // starting registers states
  int tracker = 3;
  int counter;
  int num;
  int constArrPos = 1;
  int registerTrack = 1;

  for(counter = 2; counter <= 64; ++tracker) {
    for(num = 2; num < tracker; ++num)
      if(tracker % num == 0)
        break;

    if(num == tracker) {
      // Next prime found
      pos = 31;
      data.input = cbrt((double)tracker);

      bitset<sizeof(double) * CHAR_BIT> bits(data.output);

      // Account for shifting bits as the integral portion
      // (left of the decimal point) starts surpassing powers
      // of 2
      double temp;
      modf(data.input, &temp);
      int tempInt = (int)temp;
      int expShift = 0;
      while(tempInt > 1 << expShift) {
        tempInt -= 1l << expShift;
        ++expShift;
      }

      val = 0;
      for(int bitPos = 51 - expShift; bitPos > 19 - expShift; --bitPos) {
        if (bits[bitPos] == 1)
          val += 1ul << pos;

        --pos;
      }

      constArray[constArrPos] = val;
      ++constArrPos;

      if(registerTrack < 8) {
        // Calculate register state value for current prime
        pos = 31;
        data.input = sqrt((double)tracker);

        bitset<sizeof(double) * CHAR_BIT> bits(data.output);

        modf(data.input, &temp);
        tempInt = (int)temp;
        expShift = 0;
        while(tempInt > 1l << expShift) {
          tempInt -= 1l << expShift;
          ++expShift;
        }

        val = 0;
        for(int bitPos = 51 - expShift; bitPos > 19 - expShift; --bitPos) {
          if (bits[bitPos] == 1)
            val += 1l << pos;

          --pos;
        }

        registers[registerTrack] = val;
        ++registerTrack;
      }

      ++counter;
    }
  }
}

void sha256processBlock(bool block[512], uint32_t registers[8], uint32_t constants[64]) {
  /* Create message schedule */
  uint32_t schedule[64];

  generateSchedule256(block, schedule);

  /* Begin compression process */
  for(short word = 0; word < 64; ++word) {
    uint32_t scheduleWord = schedule[word];
    uint32_t constantWord = constants[word];

    /* Create first temporary word used to change state registers */

    // Generate first temporary word using the resulting word from passing
    // the word in the 5th register to the upper sigma 1 function
    bool tempWord1[32];
    upperSigma1_256(tempWord1, registers[4]);

    // Generate second temporary word using the resulting word from passing
    // the 5th, 6th and 7th registers to the choice function
    bool tempWord2[32];
    choice(tempWord2, registers[4], registers[5], registers[6]);

    // Temp word 3 is simply the 8th register, temp word 4 is the schedule word
    // and temp word 5 is the constant word
    uint32_t val = registers[7];
    bool tempWord3[32];
    bool tempWord4[32];
    bool tempWord5[32];
    short wordPos = 0;
    for(short bitPos = 31; bitPos >= 0; --bitPos) {
      tempWord3[bitPos] = val & (1l << wordPos);
      tempWord4[bitPos] = scheduleWord & (1l << wordPos);
      tempWord5[bitPos] = constantWord & (1l << wordPos);

      ++wordPos;
    }

    // Add all words up taken at module 2^32 to get the first final temp word
    unsigned long finTempVal = 0;

    int bitTrack = 0;
    for(short bitPos = 31; bitPos >= 0; --bitPos) {
      if(tempWord1[bitPos])
        finTempVal += 1l << bitTrack;

      if(tempWord2[bitPos])
        finTempVal += 1l << bitTrack;

      if(tempWord3[bitPos])
        finTempVal += 1l << bitTrack;

      if(tempWord4[bitPos])
        finTempVal += 1l << bitTrack;

      if(tempWord5[bitPos])
        finTempVal += 1l << bitTrack;

      ++bitTrack;
    }

    uint32_t finalTemp1 = finTempVal % 4294967296;

    /* Create second temporary word used to change state registers */

    // Generate first temporary word using the resulting word from passing
    // the word in the first register to the upper sigma 0 function
    upperSigma0_256(tempWord1, registers[0]);
    unsigned long val1 = 0;
    bitTrack = 31;
    for(bool bit: tempWord1) {
      if(bit)
        val1 += 1l << bitTrack;
      --bitTrack;
    }

    // Generate second temporary word using the resulting word from passing
    // the 1st, 2nd and 3rd registers to the majority function
    majority(tempWord2, registers[0], registers[1], registers[2]);
    unsigned long val2 = 0;
    bitTrack = 31;
    for(bool bit: tempWord2) {
      if(bit)
        val2 += 1l << bitTrack;
      --bitTrack;
    }

    // Add all words up taken at module 2^32 to get the second final temp word
    finTempVal = val1 + val2;

    uint32_t finalTemp2 = finTempVal % 4294967296;

    /* Update state registers */

    // Shift register values to the right, discarding the value held in
    // register 8
    for(int iter = 7; iter > 0; --iter)
      registers[iter] = registers[iter - 1];

    // Fill first register position with the result of adding together the two
    // temporary words generated above taken modulo 2^32
    finTempVal = 0;
    for(short bitPos = 31; bitPos >= 0; --bitPos) {
      if(finalTemp1 & (1 << bitPos))
        finTempVal += 1l << bitPos;

      if(finalTemp2 & (1 << bitPos))
        finTempVal += 1l << bitPos;
    }

    uint32_t finalWord = finTempVal % 4294967296;

    registers[0] = finalWord;

    // Switch register 5's value with the resulting word from adding together
    // the 5th register value and the value of the first final temporary word
    // generated above taken modulo 2^32
    finTempVal = 0;
    for(short bitPos = 31; bitPos >= 0; --bitPos) {
      if(registers[4] & (1l << bitPos))
        finTempVal += 1l << bitPos;

      if(finalTemp1 & (1 << bitPos))
        finTempVal += 1l << bitPos;
    }

    finalWord = finTempVal % 4294967296;

    registers[4] = finalWord;
  }
}

string sha256(string data) {
  // Calculate the amount of bits needed to fill pad buffer
  unsigned long padLength = data.length() * 8; // Each character in the data is 8
                                               // bits
  unsigned long lengthHolder = padLength; // Saved for later to add to the end
                                          // of the pad buffer

  // Calculates the exact size the pad buffer needs to be to fit all the bits
  padLength = (512 * (padLength / 512 + 1));

  if(lengthHolder + 1 > padLength - 64)
    padLength += 512;

  // Create array to represent the pad buffer of bits
  bool padBuffer[padLength];

  // Zero out pad buffer
  for(int fill = 0; fill < padLength; ++fill)
    padBuffer[fill] = 0;

  /* Fill pad buffer */
  // Fill with bits taken from every byte of the given data
  int padPos = 0;
  for(int dataPos = 0; dataPos < data.length(); ++dataPos) {
    uint8_t dataVal = data.at(dataPos);

    for(int bitPos = 7; bitPos >= 0; --bitPos) {
      padBuffer[padPos] = dataVal & (1l << bitPos);
      ++padPos;
    }
  }

  // Add a 1 bit
  padBuffer[padPos] = 1;

  // Fill pad with 0s until 64 bits of space remain:
  // This is already done after we initialize the array
  // since we zero it out to get rid of any garbage left
  // in memory

  padPos = padLength - 1;

  uint64_t val = lengthHolder;
  uint64_t temp = 0;

  // This makes sure that only the bits representing the bit size
  // of the data is accurately inserted into pad buffer
  for(int bitPos = 0; bitPos <= 63; ++bitPos) {
    bool bit = val & (1l << bitPos);

    padBuffer[padPos] = bit;

    if(bit) {
      temp += 1l << bitPos;
      if(temp == val)
        break;
    }

    --padPos;
  }

  // Create constants array and initial state registers
  uint32_t constants[64];
  uint32_t stateRegisters[8];
  generateStartingHashState256(constants, stateRegisters);

  // Process pad buffer in 512 bit blocks
  bool block[512];

  int blockTrack = 0;
  uint32_t registerStateSave[8];
  for(int bitCount = 0; bitCount < padLength; ++bitCount) {
    block[blockTrack] = padBuffer[bitCount];
    ++blockTrack;

    if(blockTrack == 512) {
      // Save the state of the current registers
      short pos = 0;
      for(uint32_t val: stateRegisters)
        registerStateSave[pos++] = val;

      sha256processBlock(block, stateRegisters, constants);

      // Add saved register state to the newly processed register state to
      // obtain the final resulting register state of the current iteration
      unsigned long tempVal = 0;
      for(short pointer = 0; pointer < 8; ++pointer) {
        for(short bitPos = 31; bitPos >= 0; --bitPos) {
          if(stateRegisters[pointer] & (1l << bitPos))
            tempVal += 1l << bitPos;

          if(registerStateSave[pointer] & (1l << bitPos))
            tempVal += 1l << bitPos;
        }

        uint32_t newStateVal = tempVal % 4294967296;

        stateRegisters[pointer] = newStateVal;

        tempVal = 0;
      }

      blockTrack = 0;
    }
  }

  /* Convert resulting state registers to hexadecimal notation */

  return hexDigest(stateRegisters, 8);
}

/*---------------------------------------------------------------------------*/
/*                           Begin SHA224 Section                            */
/*---------------------------------------------------------------------------*/

/*
  SHA224's algorithm design is exactly the same as SHA256's, with the
  following changes:

  - State registers are created using the 9th through 16th primes instead
    of the first 8
  - Output is generated by omitting the 8th state register's value
*/

void generateStartingHashState224(uint32_t constArray[64], uint32_t registers[8]) {
  union {
    double input;
    uint64_t output;
  } data;

  // Generates the first 64 primes and uses the fractional bits of the cube
  // roots of these primes to create our constants and the fractional portion
  // of their square roots for the starting states of the registers

  // Calculate cube root of 2 and retrieve the constant
  data.input = cbrt(2.0);

  bitset<sizeof(double) * CHAR_BIT> bits(data.output);

  uint32_t val = 0;
  int pos = 31;
  for(int bitPos = 51; bitPos > 19; --bitPos) {
    if (bits[bitPos] == 1)
      val += 1l << pos;

    --pos;
  }

  constArray[0] = val;

  // Calculate the remaining 63 primes and their resulting constants and
  // starting registers states
  int tracker = 3;
  int counter;
  int num;
  int constArrPos = 1;
  int primeTrack = 1;
  int registerTrack = 0;

  for(counter = 2; counter <= 64; ++tracker) {
    for(num = 2; num < tracker; ++num)
      if(tracker % num == 0)
        break;

    if(num == tracker) {
      // Next prime found
      ++primeTrack;

      pos = 31;
      data.input = cbrt((double)tracker);

      bitset<sizeof(double) * CHAR_BIT> bits(data.output);

      // Account for shifting bits as the integral portion
      // (left of the decimal point) starts surpassing powers
      // of 2
      double temp;
      modf(data.input, &temp);
      int tempInt = (int)temp;
      int expShift = 0;
      while(tempInt > 1 << expShift) {
        tempInt -= 1l << expShift;
        ++expShift;
      }

      val = 0;
      for(int bitPos = 51 - expShift; bitPos > 19 - expShift; --bitPos) {
        if (bits[bitPos] == 1)
          val += 1ul << pos;

        --pos;
      }

      constArray[constArrPos] = val;
      ++constArrPos;

      ++counter;
    }
  }

  // Initialize starting register states. Since these values are based on the
  // second set of 32 bits of the fractional portion of the square roots of
  // the 9th through 16th primes, it's easier to set these manually.
  registers[0] = 3238371032; // 0xc1059ed8
  registers[1] = 914150663;  // 0x367cd507
  registers[2] = 812702999;  // 0x3070dd17
  registers[3] = 4144912697; // 0xf70e5939
  registers[4] = 4290775857; // 0xffc00b31
  registers[5] = 1750603025; // 0x68581511
  registers[6] = 1694076839; // 0x64f98fa7
  registers[7] = 3204075428; // 0xbefa4fa4
}

string sha224(string data) {
  // Calculate the amount of bits needed to fill pad buffer
  unsigned long padLength = data.length() * 8; // Each character in the data is 8
                                               // bits
  unsigned long lengthHolder = padLength; // Saved for later to add to the end
                                          // of the pad buffer

  // Calculates the exact size the pad buffer needs to be to fit all the bits
  padLength = (512 * (padLength / 512 + 1));

  if(lengthHolder + 1 > padLength - 64)
    padLength += 512;

  // Create array to represent the pad buffer of bits
  bool padBuffer[padLength];

  // Zero out pad buffer
  for(int fill = 0; fill < padLength; ++fill)
    padBuffer[fill] = 0;

  /* Fill pad buffer */
  // Fill with bits taken from every byte of the given data
  int padPos = 0;
  for(int dataPos = 0; dataPos < data.length(); ++dataPos) {
    uint8_t dataVal = data.at(dataPos);

    for(int bitPos = 7; bitPos >= 0; --bitPos) {
      padBuffer[padPos] = dataVal & (1l << bitPos);
      ++padPos;
    }
  }

  // Add a 1 bit
  padBuffer[padPos] = 1;

  // Fill pad with 0s until 64 bits of space remain:
  // This is already done after we initialize the array
  // since we zero it out to get rid of any garbage left
  // in memory

  padPos = padLength - 1;

  uint64_t val = lengthHolder;
  uint64_t temp = 0;

  // This makes sure that only the bits representing the bit size
  // of the data is accurately inserted into pad buffer
  for(int bitPos = 0; bitPos <= 63; ++bitPos) {
    bool bit = val & (1l << bitPos);

    padBuffer[padPos] = bit;

    if(bit) {
      temp += 1l << bitPos;
      if(temp == val)
        break;
    }

    --padPos;
  }

  // Create constants array and initial state registers
  uint32_t constants[64];
  uint32_t stateRegisters[8];
  generateStartingHashState224(constants, stateRegisters);

  // Process pad buffer in 512 bit blocks
  bool block[512];

  int blockTrack = 0;
  uint32_t registerStateSave[8];
  for(int bitCount = 0; bitCount < padLength; ++bitCount) {
    block[blockTrack] = padBuffer[bitCount];
    ++blockTrack;

    if(blockTrack == 512) {
      // Save the state of the current registers
      short pos = 0;
      for(uint32_t val: stateRegisters)
        registerStateSave[pos++] = val;

      // SHA224 and 256 process their blocks the same
      sha256processBlock(block, stateRegisters, constants);

      // Add saved register state to the newly processed register state to
      // obtain the final resulting register state of the current iteration
      unsigned long tempVal = 0;
      for(short pointer = 0; pointer < 8; ++pointer) {
        for(short bitPos = 31; bitPos >= 0; --bitPos) {
          if(stateRegisters[pointer] & (1l << bitPos))
            tempVal += 1l << bitPos;

          if(registerStateSave[pointer] & (1l << bitPos))
            tempVal += 1l << bitPos;
        }

        uint32_t newStateVal = tempVal % 4294967296;

        stateRegisters[pointer] = newStateVal;

        tempVal = 0;
      }

      blockTrack = 0;
    }
  }

  /* Convert resulting state registers to hexadecimal notation */

  return hexDigest(stateRegisters, 7);
}

/*---------------------------------------------------------------------------*/
/*                           Begin SHA512 Section                            */
/*---------------------------------------------------------------------------*/

/*
  SHA512 is fundamentally the same in it's design as SHA256, with the
  following changes:

  - Blocks are processed in 1024 bit chunks
  - Initial register values and constants values are extended to 64 bits
  - There are 80 rounds instead of 64
  - The message schedule array has 80 64 bit words
  - Shift and rotation amounts are different
*/

/*
  The lower sigma 0 (σ0) function for SHA384 and SHA512, defined as follows:

  Given a 64 bit number, create another 64 bit number by performing the following

  Rotational Right Shift of 1 bit from the original number XORd with
  Rotational Right Shift of 8 bits from the original number XORd with
  Right Shift of 7 bits from the original number
*/
void lowerSigma0_512(bool word[64], uint64_t val) {
  // Temp word 1 is the resulting word from performing a rotational right
  // shift on originally passed word 1 time
  bool tempWord1[64];
  rotationalRightShift64(tempWord1, val, 1);

  // Temp word 2 is the resulting word from performing a rotational right
  // shift on originally passed word 8 times
  bool tempWord2[64];
  rotationalRightShift64(tempWord2, val, 8);

  // Temp word 3 is the result of a right shift of 7
  bool tempWord3[64];
  uint64_t tempVal = val >> 7;
  short wordPos = 0;
  for(short bitPos = 63; bitPos >= 0; --bitPos) {
    bool bit = tempVal & (1ull << bitPos);

    tempWord3[wordPos++] = bit;
  }

  // Resulting word comes from XORing all 3 generated temporary words
  for(short bitPos = 0; bitPos < 64; ++bitPos)
    word[bitPos] = tempWord1[bitPos] ^ tempWord2[bitPos] ^ tempWord3[bitPos];
}

/*
  The lower sigma 1 (σ1) function for SHA384 and SHA512, defined as follows:

  Given a 64 bit number, create another 64 bit number by performing the following

  Rotational Right Shift of 19 bits from the original number XORd with
  Rotational Right Shift of 61 bits from the original number XORd with
  Right Shift of 6 bits from the original number
*/
void lowerSigma1_512(bool word[64], uint64_t val) {
  // Temp word 1 is the resulting word from performing a rotational right
  // shift on originally passed word 19 times
  bool tempWord1[64];
  rotationalRightShift64(tempWord1, val, 19);

  // Temp word 2 is the resulting word from performing a rotational right
  // shift on originally passed word 61 times
  bool tempWord2[64];
  rotationalRightShift64(tempWord2, val, 61);

  // Temp word 3 is the result of a right shift of 6
  bool tempWord3[64];
  uint64_t tempVal = val >> 6;
  short wordPos = 0;
  for(short bitPos = 63; bitPos >= 0; --bitPos) {
    bool bit = tempVal & (1ull << bitPos);

    tempWord3[wordPos++] = bit;
  }

  // Resulting word comes from XORing all 3 generated temporary words
  for(short bitPos = 0; bitPos < 64; ++bitPos)
    word[bitPos] = tempWord1[bitPos] ^ tempWord2[bitPos] ^ tempWord3[bitPos];
}

/*
  The upper sigma 0 (Σ0) function for SHA384 and SHA512, defined as follows:

  Given a 64 bit number, create another 64 bit number by performing the following

  Rotational Right Shift of 28 bits from the original number XORd with
  Rotational Right Shift of 34 bits from the original number XORd with
  Rotational Right Shift of 39 bits from the original number
*/
void upperSigma0_512(bool word[64], uint64_t val) {
  // Temp word 1 is the resulting word from performing a rotational right
  // shift on originally passed word 2 times
  bool tempWord1[64];
  rotationalRightShift64(tempWord1, val, 28);

  // Temp word 2 is the resulting word from performing a rotational right
  // shift on originally passed word 13 times
  bool tempWord2[64];
  rotationalRightShift64(tempWord2, val, 34);

  // Temp word 3 is the resulting word from performing a rotational right
  // shift on originally passed word 22 times
  bool tempWord3[64];
  rotationalRightShift64(tempWord3, val, 39);

  // Resulting word comes from XORing all 3 generated temporary words
  for(short bitPos = 0; bitPos < 64; ++bitPos)
    word[bitPos] = tempWord1[bitPos] ^ tempWord2[bitPos] ^ tempWord3[bitPos];
}

/*
  The upper sigma 1 (Σ1) function for SHA384 and SHA512, defined as follows:

  Given a 64 bit number, create another 64 bit number by performing the following

  Rotational Right Shift of 14 bits from the original number XORd with
  Rotational Right Shift of 18 bits from the original number XORd with
  Rotational Right Shift of 41 bits from the original number
*/
void upperSigma1_512(bool word[64], uint64_t val) {
  // Temp word 1 is the resulting word from performing a rotational right
  // shift on originally passed word 6 times
  bool tempWord1[64];
  rotationalRightShift64(tempWord1, val, 14);

  // Temp word 2 is the resulting word from performing a rotational right
  // shift on originally passed word 11 times
  bool tempWord2[64];
  rotationalRightShift64(tempWord2, val, 18);

  // Temp word 3 is the resulting word from performing a rotational right
  // shift on originally passed word 25 times
  bool tempWord3[64];
  rotationalRightShift64(tempWord3, val, 41);

  // Resulting word comes from XORing all 3 generated temporary words
  for(short bitPos = 0; bitPos < 64; ++bitPos)
    word[bitPos] = tempWord1[bitPos] ^ tempWord2[bitPos] ^ tempWord3[bitPos];
}

void generateSchedule512(bool block[1024], uint64_t schedule[80]) {
  // Create the first 16 64-bit words using the message block
  short bitCount = 0;
  short schedulePos = 0;
  short bitPos = 63;
  bool word[64];
  for(int blockCount = 0; blockCount < 1024; ++blockCount) {
    word[bitCount] = block[blockCount];
    ++bitCount;

    if(bitCount == 64) {
      uint64_t val = 0;

      for (bool wordBit: word) {
        if (wordBit)
          val += 1l << bitPos;
        --bitPos;
      }

      schedule[schedulePos] = val;
      ++schedulePos;

      bitCount = 0;
      bitPos = 63;
    }
  }

  // Expand the schedule to 80 64-bit words
  while(schedulePos < 80) {
    bool word1[64];
    lowerSigma0_512(word1, schedule[schedulePos - 15]);

    bool word2[64];
    lowerSigma1_512(word2, schedule[schedulePos - 2]);

    short wordPos = 0;
    bool word3[64];
    uint64_t val = schedule[schedulePos - 7];
    while (bitPos >= 0) {
      word3[wordPos] = val & (1ull << bitPos);
      ++wordPos;
      --bitPos;
    }

    bitPos = 63;
    wordPos = 0;
    bool word4[64];
    val = schedule[schedulePos - 16];
    while (bitPos >= 0) {
      word4[wordPos] = val & (1ull << bitPos);
      ++wordPos;
      --bitPos;
    }

    bitPos = 63;

    // Add them all and take the result mod 2^64
    uint128_t tempValue = 0;
    short bitTrack = 0;
    for (short bitPos = 63; bitPos >= 0; --bitPos) {
      if(word1[bitPos])
        tempValue += 1ull << bitTrack;

      if(word2[bitPos])
        tempValue += 1ull << bitTrack;

      if(word3[bitPos])
        tempValue += 1ull << bitTrack;

      if(word4[bitPos])
        tempValue += 1ull << bitTrack;

      ++bitTrack;
    }

    uint64_t scheduleWord = tempValue % bigModulo;

    schedule[schedulePos] = scheduleWord;
    ++schedulePos;
  }
}

void sha512processBlock(bool block[1024], uint64_t registers[8], uint64_t constants[80]) {
  /* Create message schedule */
  uint64_t schedule[80];

  generateSchedule512(block, schedule);

  /* Begin compression process */
  for(short word = 0; word < 80; ++word) {
    uint64_t scheduleWord = schedule[word];
    uint64_t constantWord = constants[word];

    /* Create first temporary word used to change state registers */

    // Generate first temporary word using the resulting word from passing
    // the word in the 5th register to the upper sigma 1 function
    bool tempWord1[64];
    upperSigma1_512(tempWord1, registers[4]);

    // Generate second temporary word using the resulting word from passing
    // the 5th, 6th and 7th registers to the choice function
    bool tempWord2[64];
    choice64(tempWord2, registers[4], registers[5], registers[6]);

    // Temp word 3 is simply the 8th register, temp word 4 is the schedule word
    // and temp word 5 is the constant word
    uint64_t val = registers[7];
    bool tempWord3[64];
    bool tempWord4[64];
    bool tempWord5[64];
    short wordPos = 0;
    for(short bitPos = 63; bitPos >= 0; --bitPos) {
      tempWord3[bitPos] = val & (1ull << wordPos);
      tempWord4[bitPos] = scheduleWord & (1ull << wordPos);
      tempWord5[bitPos] = constantWord & (1ull << wordPos);

      ++wordPos;
    }

    // Add all words up taken at module 2^64 to get the first final temp word
    uint128_t finTempVal = 0;

    short bitTrack = 0;
    for(short bitPos = 63; bitPos >= 0; --bitPos) {
      if(tempWord1[bitPos])
        finTempVal += 1ull << bitTrack;

      if(tempWord2[bitPos])
        finTempVal += 1ull << bitTrack;

      if(tempWord3[bitPos])
        finTempVal += 1ull << bitTrack;

      if(tempWord4[bitPos])
        finTempVal += 1ull << bitTrack;

      if(tempWord5[bitPos])
        finTempVal += 1ull << bitTrack;

      ++bitTrack;
    }

    uint64_t finalTemp1 = finTempVal % bigModulo;

    /* Create second temporary word used to change state registers */

    // Generate first temporary word using the resulting word from passing
    // the word in the first register to the upper sigma 0 function
    upperSigma0_512(tempWord1, registers[0]);
    uint128_t val1 = 0;
    bitTrack = 63;
    for(bool bit: tempWord1) {
      if(bit)
        val1 += 1ull << bitTrack;
      --bitTrack;
    }

    // Generate second temporary word using the resulting word from passing
    // the 1st, 2nd and 3rd registers to the majority function
    majority64(tempWord2, registers[0], registers[1], registers[2]);
    uint128_t val2 = 0;
    bitTrack = 63;
    for(bool bit: tempWord2) {
      if(bit)
        val2 += 1ull << bitTrack;
      --bitTrack;
    }

    // Add all words up taken at module 2^64 to get the second final temp word
    finTempVal = val1 + val2;

    uint64_t finalTemp2 = finTempVal % bigModulo;

    /* Update state registers */

    // Shift register values to the right, discarding the value held in
    // register 8
    for(int iter = 7; iter > 0; --iter)
      registers[iter] = registers[iter - 1];

    // Fill first register position with the result of adding together the two
    // temporary words generated above taken modulo 2^64
    finTempVal = 0;
    for(short bitPos = 63; bitPos >= 0; --bitPos) {
      if(finalTemp1 & (1ull << bitPos))
        finTempVal += 1ull << bitPos;

      if(finalTemp2 & (1ull << bitPos))
        finTempVal += 1ull << bitPos;
    }

    uint64_t finalWord = finTempVal % bigModulo;

    registers[0] = finalWord;

    // Switch register 5's value with the resulting word from adding together
    // the 5th register value and the value of the first final temporary word
    // generated above taken modulo 2^64
    finTempVal = 0;
    for(short bitPos = 63; bitPos >= 0; --bitPos) {
      if(registers[4] & (1ull << bitPos))
        finTempVal += 1ull << bitPos;

      if(finalTemp1 & (1ull << bitPos))
        finTempVal += 1ull << bitPos;
    }

    finalWord = finTempVal % bigModulo;

    registers[4] = finalWord;
  }
}

string sha512(string data) {
  // Calculate the amount of bits needed to fill pad buffer
  uint128_t padLength = data.length() * 8; // Each character in the data is 8
                                           // bits
  uint128_t lengthHolder = padLength; // Saved for later to add to the end
                                      // of the pad buffer

  // Calculates the exact size the pad buffer needs to be to fit all the bits
  padLength = (1024 * (padLength / 1024 + 1));

  if(lengthHolder + 1 > padLength - 128)
    padLength += 1024;

  // Create array to represent the pad buffer of bits
  bool padBuffer[padLength];

  // Zero out pad buffer
  for(uint128_t fill = 0; fill < padLength; ++fill)
    padBuffer[fill] = 0;

  /* Fill pad buffer */
  // Fill with bits taken from every byte of the given data
  uint128_t padPos = 0;
  for(int dataPos = 0; dataPos < data.length(); ++dataPos) {
    uint8_t dataVal = data.at(dataPos);

    for(int bitPos = 7; bitPos >= 0; --bitPos) {
      padBuffer[padPos] = dataVal & (1l << bitPos);
      ++padPos;
    }
  }

  // Add a 1 bit
  padBuffer[padPos] = 1;

  // Fill pad with 0s until 128 bits of space remain:
  // This is already done after we initialize the array
  // since we zero it out to get rid of any garbage left
  // in memory

  padPos = padLength - 1;

  uint128_t val = lengthHolder;
  uint128_t temp = 0;

  // This makes sure that only the bits representing the bit size
  // of the data is accurately inserted into pad buffer
  for(int bitPos = 0; bitPos <= 127; ++bitPos) {
    bool bit = val & ((uint128_t)1 << bitPos);

    padBuffer[padPos] = bit;

    if(bit) {
      temp += 1ull << bitPos;
      if(temp == val)
        break;
    }

    --padPos;
  }

  // Create constants array and initial state registers
  uint64_t constants[80] = {0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f,
                            0xe9b5dba58189dbbc, 0x3956c25bf348b538, 0x59f111f1b605d019,
                            0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242,
                            0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
                            0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235,
                            0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3,
                            0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65, 0x2de92c6f592b0275,
                            0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
                            0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f,
                            0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725,
                            0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc,
                            0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
                            0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6,
                            0x92722c851482353b, 0xa2bfe8a14cf10364, 0xa81a664bbc423001,
                            0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218,
                            0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
                            0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99,
                            0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb,
                            0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc,
                            0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
                            0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915,
                            0xc67178f2e372532b, 0xca273eceea26619c, 0xd186b8c721c0c207,
                            0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba,
                            0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
                            0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc,
                            0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a,
                            0x5fcb6fab3ad6faec, 0x6c44198c4a475817};
  
  uint64_t stateRegisters[8];
  stateRegisters[0] = 7640891576956012808;  // 0x6a09e667f3bcc908
  stateRegisters[1] = 13503953896175478587; // 0xbb67ae8584caa73b
  stateRegisters[2] = 4354685564936845355;  // 0x3c6ef372fe94f82b
  stateRegisters[3] = 11912009170470909681; // 0xa54ff53a5f1d36f1
  stateRegisters[4] = 5840696475078001361;  // 0x510e527fade682d1
  stateRegisters[5] = 11170449401992604703; // 0x9b05688c2b3e6c1f
  stateRegisters[6] = 2270897969802886507;  // 0x1f83d9abfb41bd6b
  stateRegisters[7] = 6620516959819538809;  // 0x5be0cd19137e2179

  // Process pad buffer in 1024 bit blocks
  bool block[1024];

  int blockTrack = 0;
  uint64_t registerStateSave[8];
  for(int bitCount = 0; bitCount < padLength; ++bitCount) {
    block[blockTrack] = padBuffer[bitCount];
    ++blockTrack;

    if(blockTrack == 1024) {
      // Save the state of the current registers
      short pos = 0;
      for(uint64_t val: stateRegisters)
        registerStateSave[pos++] = val;

      sha512processBlock(block, stateRegisters, constants);

      // Add saved register state to the newly processed register state to
      // obtain the final resulting register state of the current iteration
      uint128_t tempVal = 0;
      for(short pointer = 0; pointer < 8; ++pointer) {
        for(short bitPos = 63; bitPos >= 0; --bitPos) {
          if(stateRegisters[pointer] & (1ull << bitPos))
            tempVal += 1ull << bitPos;

          if(registerStateSave[pointer] & (1ull << bitPos))
            tempVal += 1ull << bitPos;
        }

        uint64_t newStateVal = tempVal % bigModulo;

        stateRegisters[pointer] = newStateVal;

        tempVal = 0;
      }

      blockTrack = 0;
    }
  }

  /* Convert resulting state registers to hexadecimal notation */

  return hexDigest(stateRegisters, 8);
}

/*---------------------------------------------------------------------------*/
/*                           Begin SHA384 Section                            */
/*---------------------------------------------------------------------------*/

/*
  SHA384's algorithm design is exactly the same as SHA512's, with the
  following changes:

  - State registers are created using the 9th through 16th primes instead
    of the first 8
  - Output is generated by omitting the 7th and 8th state register's values
*/

string sha384(string data) {
  // Calculate the amount of bits needed to fill pad buffer
  uint128_t padLength = data.length() * 8; // Each character in the data is 8
                                           // bits
  uint128_t lengthHolder = padLength; // Saved for later to add to the end
                                      // of the pad buffer

  // Calculates the exact size the pad buffer needs to be to fit all the bits
  padLength = (1024 * (padLength / 1024 + 1));

  if(lengthHolder + 1 > padLength - 128)
    padLength += 1024;

  // Create array to represent the pad buffer of bits
  bool padBuffer[padLength];

  // Zero out pad buffer
  for(uint128_t fill = 0; fill < padLength; ++fill)
    padBuffer[fill] = 0;

  /* Fill pad buffer */
  // Fill with bits taken from every byte of the given data
  uint128_t padPos = 0;
  for(int dataPos = 0; dataPos < data.length(); ++dataPos) {
    uint8_t dataVal = data.at(dataPos);

    for(int bitPos = 7; bitPos >= 0; --bitPos) {
      padBuffer[padPos] = dataVal & (1l << bitPos);
      ++padPos;
    }
  }

  // Add a 1 bit
  padBuffer[padPos] = 1;

  // Fill pad with 0s until 128 bits of space remain:
  // This is already done after we initialize the array
  // since we zero it out to get rid of any garbage left
  // in memory

  padPos = padLength - 1;

  uint128_t val = lengthHolder;
  uint128_t temp = 0;

  // This makes sure that only the bits representing the bit size
  // of the data is accurately inserted into pad buffer
  for(int bitPos = 0; bitPos <= 127; ++bitPos) {
    bool bit = val & ((uint128_t)1 << bitPos);

    padBuffer[padPos] = bit;

    if(bit) {
      temp += 1ull << bitPos;
      if(temp == val)
        break;
    }

    --padPos;
  }

  // Create constants array and initial state registers
  uint64_t constants[80] = {0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f,
                            0xe9b5dba58189dbbc, 0x3956c25bf348b538, 0x59f111f1b605d019,
                            0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242,
                            0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
                            0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235,
                            0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3,
                            0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65, 0x2de92c6f592b0275,
                            0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
                            0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f,
                            0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725,
                            0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc,
                            0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
                            0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6,
                            0x92722c851482353b, 0xa2bfe8a14cf10364, 0xa81a664bbc423001,
                            0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218,
                            0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
                            0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99,
                            0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb,
                            0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc,
                            0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
                            0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915,
                            0xc67178f2e372532b, 0xca273eceea26619c, 0xd186b8c721c0c207,
                            0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba,
                            0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
                            0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc,
                            0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a,
                            0x5fcb6fab3ad6faec, 0x6c44198c4a475817};
  
  uint64_t stateRegisters[8];
  stateRegisters[0] = 14680500436340154072; // 0xcbbb9d5dc1059ed8
  stateRegisters[1] = 7105036623409894663;  // 0x629a292a367cd507
  stateRegisters[2] = 10473403895298186519; // 0x9159015a3070dd17
  stateRegisters[3] = 1526699215303891257;  // 0x152fecd8f70e5939
  stateRegisters[4] = 7436329637833083697;  // 0x67332667ffc00b31
  stateRegisters[5] = 10282925794625328401; // 0x8eb44a8768581511
  stateRegisters[6] = 15784041429090275239; // 0xdb0c2e0d64f98fa7
  stateRegisters[7] = 5167115440072839076;  // 0x47b5481dbefa4fa4

  // Process pad buffer in 1024 bit blocks
  bool block[1024];

  int blockTrack = 0;
  uint64_t registerStateSave[8];
  for(int bitCount = 0; bitCount < padLength; ++bitCount) {
    block[blockTrack] = padBuffer[bitCount];
    ++blockTrack;

    if(blockTrack == 1024) {
      // Save the state of the current registers
      short pos = 0;
      for(uint64_t val: stateRegisters)
        registerStateSave[pos++] = val;

      sha512processBlock(block, stateRegisters, constants);

      // Add saved register state to the newly processed register state to
      // obtain the final resulting register state of the current iteration
      uint128_t tempVal = 0;
      for(short pointer = 0; pointer < 8; ++pointer) {
        for(short bitPos = 63; bitPos >= 0; --bitPos) {
          if(stateRegisters[pointer] & (1ull << bitPos))
            tempVal += 1ull << bitPos;

          if(registerStateSave[pointer] & (1ull << bitPos))
            tempVal += 1ull << bitPos;
        }

        uint64_t newStateVal = tempVal % bigModulo;

        stateRegisters[pointer] = newStateVal;

        tempVal = 0;
      }

      blockTrack = 0;
    }
  }

  /* Convert resulting state registers to hexadecimal notation */

  return hexDigest(stateRegisters, 6);
}

/*---------------------------------------------------------------------------*/
/*                         Begin SHA512/224 Section                          */
/*---------------------------------------------------------------------------*/

/*
  SHA512/224 is exactly the same as SHA512 and SHA384, accept for the
  following changes:

  - State registers are determined by the result of the SHA512/t IV Generation
    function on the string "SHA512/224".
  - Output is truncated to 224 bits
*/

string sha512_224(string data) {
  // Calculate the amount of bits needed to fill pad buffer
  uint128_t padLength = data.length() * 8; // Each character in the data is 8
                                           // bits
  uint128_t lengthHolder = padLength; // Saved for later to add to the end
                                      // of the pad buffer

  // Calculates the exact size the pad buffer needs to be to fit all the bits
  padLength = (1024 * (padLength / 1024 + 1));

  if(lengthHolder + 1 > padLength - 128)
    padLength += 1024;

  // Create array to represent the pad buffer of bits
  bool padBuffer[padLength];

  // Zero out pad buffer
  for(uint128_t fill = 0; fill < padLength; ++fill)
    padBuffer[fill] = 0;

  /* Fill pad buffer */
  // Fill with bits taken from every byte of the given data
  uint128_t padPos = 0;
  for(int dataPos = 0; dataPos < data.length(); ++dataPos) {
    uint8_t dataVal = data.at(dataPos);

    for(int bitPos = 7; bitPos >= 0; --bitPos) {
      padBuffer[padPos] = dataVal & (1l << bitPos);
      ++padPos;
    }
  }

  // Add a 1 bit
  padBuffer[padPos] = 1;

  // Fill pad with 0s until 128 bits of space remain:
  // This is already done after we initialize the array
  // since we zero it out to get rid of any garbage left
  // in memory

  padPos = padLength - 1;

  uint128_t val = lengthHolder;
  uint128_t temp = 0;

  // This makes sure that only the bits representing the bit size
  // of the data is accurately inserted into pad buffer
  for(int bitPos = 0; bitPos <= 127; ++bitPos) {
    bool bit = val & ((uint128_t)1 << bitPos);

    padBuffer[padPos] = bit;

    if(bit) {
      temp += 1ull << bitPos;
      if(temp == val)
        break;
    }

    --padPos;
  }

  // Create constants array and initial state registers
  uint64_t constants[80] = {0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f,
                            0xe9b5dba58189dbbc, 0x3956c25bf348b538, 0x59f111f1b605d019,
                            0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242,
                            0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
                            0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235,
                            0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3,
                            0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65, 0x2de92c6f592b0275,
                            0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
                            0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f,
                            0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725,
                            0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc,
                            0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
                            0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6,
                            0x92722c851482353b, 0xa2bfe8a14cf10364, 0xa81a664bbc423001,
                            0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218,
                            0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
                            0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99,
                            0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb,
                            0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc,
                            0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
                            0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915,
                            0xc67178f2e372532b, 0xca273eceea26619c, 0xd186b8c721c0c207,
                            0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba,
                            0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
                            0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc,
                            0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a,
                            0x5fcb6fab3ad6faec, 0x6c44198c4a475817};
  
  uint64_t stateRegisters[8];
  stateRegisters[0] = 10105294471447203234; // 0x8c3d37c819544da2
  stateRegisters[1] = 8350123849800275158;  // 0x73e1996689dcd4d6
  stateRegisters[2] = 2160240930085379202;  // 0x1dfab7ae32ff9c82
  stateRegisters[3] = 7466358040605728719;  // 0x679dd514582f9fcf
  stateRegisters[4] = 1111592415079452072;  // 0x0f6d2b697bd44da8
  stateRegisters[5] = 8638871050018654530;  // 0x77d36f7304c48942
  stateRegisters[6] = 4583966954114332360;  // 0x3f9d85a86a1d36c8
  stateRegisters[7] = 1230299281376055969;  // 0x1112e6ad91d692a1

  // Process pad buffer in 1024 bit blocks
  bool block[1024];

  int blockTrack = 0;
  uint64_t registerStateSave[8];
  for(int bitCount = 0; bitCount < padLength; ++bitCount) {
    block[blockTrack] = padBuffer[bitCount];
    ++blockTrack;

    if(blockTrack == 1024) {
      // Save the state of the current registers
      short pos = 0;
      for(uint64_t val: stateRegisters)
        registerStateSave[pos++] = val;

      sha512processBlock(block, stateRegisters, constants);

      // Add saved register state to the newly processed register state to
      // obtain the final resulting register state of the current iteration
      uint128_t tempVal = 0;
      for(short pointer = 0; pointer < 8; ++pointer) {
        for(short bitPos = 63; bitPos >= 0; --bitPos) {
          if(stateRegisters[pointer] & (1ull << bitPos))
            tempVal += 1ull << bitPos;

          if(registerStateSave[pointer] & (1ull << bitPos))
            tempVal += 1ull << bitPos;
        }

        uint64_t newStateVal = tempVal % bigModulo;

        stateRegisters[pointer] = newStateVal;

        tempVal = 0;
      }

      blockTrack = 0;
    }
  }

  /* Convert resulting state registers to hexadecimal notation */

  return hexDigest(stateRegisters, 4).substr(0, 56);
}

/*---------------------------------------------------------------------------*/
/*                         Begin SHA512/256 Section                          */
/*---------------------------------------------------------------------------*/

/*
  SHA512/224 is exactly the same as SHA512 and SHA384, accept for the
  following changes:

  - State registers are determined by the result of the SHA512/t IV Generation
    function on the string "SHA512/256".
  - Output is truncated to 256 bits
*/

string sha512_256(string data) {
  // Calculate the amount of bits needed to fill pad buffer
  uint128_t padLength = data.length() * 8; // Each character in the data is 8
                                           // bits
  uint128_t lengthHolder = padLength; // Saved for later to add to the end
                                      // of the pad buffer

  // Calculates the exact size the pad buffer needs to be to fit all the bits
  padLength = (1024 * (padLength / 1024 + 1));

  if(lengthHolder + 1 > padLength - 128)
    padLength += 1024;

  // Create array to represent the pad buffer of bits
  bool padBuffer[padLength];

  // Zero out pad buffer
  for(uint128_t fill = 0; fill < padLength; ++fill)
    padBuffer[fill] = 0;

  /* Fill pad buffer */
  // Fill with bits taken from every byte of the given data
  uint128_t padPos = 0;
  for(int dataPos = 0; dataPos < data.length(); ++dataPos) {
    uint8_t dataVal = data.at(dataPos);

    for(int bitPos = 7; bitPos >= 0; --bitPos) {
      padBuffer[padPos] = dataVal & (1l << bitPos);
      ++padPos;
    }
  }

  // Add a 1 bit
  padBuffer[padPos] = 1;

  // Fill pad with 0s until 128 bits of space remain:
  // This is already done after we initialize the array
  // since we zero it out to get rid of any garbage left
  // in memory

  padPos = padLength - 1;

  uint128_t val = lengthHolder;
  uint128_t temp = 0;

  // This makes sure that only the bits representing the bit size
  // of the data is accurately inserted into pad buffer
  for(int bitPos = 0; bitPos <= 127; ++bitPos) {
    bool bit = val & ((uint128_t)1 << bitPos);

    padBuffer[padPos] = bit;

    if(bit) {
      temp += 1ull << bitPos;
      if(temp == val)
        break;
    }

    --padPos;
  }

  // Create constants array and initial state registers
  uint64_t constants[80] = {0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f,
                            0xe9b5dba58189dbbc, 0x3956c25bf348b538, 0x59f111f1b605d019,
                            0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242,
                            0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
                            0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235,
                            0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3,
                            0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65, 0x2de92c6f592b0275,
                            0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
                            0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f,
                            0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725,
                            0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc,
                            0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
                            0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6,
                            0x92722c851482353b, 0xa2bfe8a14cf10364, 0xa81a664bbc423001,
                            0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218,
                            0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
                            0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99,
                            0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb,
                            0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc,
                            0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
                            0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915,
                            0xc67178f2e372532b, 0xca273eceea26619c, 0xd186b8c721c0c207,
                            0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba,
                            0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
                            0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc,
                            0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a,
                            0x5fcb6fab3ad6faec, 0x6c44198c4a475817};
  
  uint64_t stateRegisters[8];
  stateRegisters[0] = 2463787394917988140;  // 0x22312194fc2bf72c
  stateRegisters[1] = 11481187982095705282; // 0x9f555fa3c84c64c2
  stateRegisters[2] = 2563595384472711505;  // 0x2393b86b6f53b151
  stateRegisters[3] = 10824532655140301501; // 0x963877195940eabd
  stateRegisters[4] = 10819967247969091555; // 0x96283ee2a88effe3
  stateRegisters[5] = 13717434660681038226; // 0xbe5e1e2553863992
  stateRegisters[6] = 3098927326965381290;  // 0x2b0199fc2c85b8aa
  stateRegisters[7] = 1060366662362279074;  // 0x0eb72ddc81c52ca2

  // Process pad buffer in 1024 bit blocks
  bool block[1024];

  int blockTrack = 0;
  uint64_t registerStateSave[8];
  for(int bitCount = 0; bitCount < padLength; ++bitCount) {
    block[blockTrack] = padBuffer[bitCount];
    ++blockTrack;

    if(blockTrack == 1024) {
      // Save the state of the current registers
      short pos = 0;
      for(uint64_t val: stateRegisters)
        registerStateSave[pos++] = val;

      sha512processBlock(block, stateRegisters, constants);

      // Add saved register state to the newly processed register state to
      // obtain the final resulting register state of the current iteration
      uint128_t tempVal = 0;
      for(short pointer = 0; pointer < 8; ++pointer) {
        for(short bitPos = 63; bitPos >= 0; --bitPos) {
          if(stateRegisters[pointer] & (1ull << bitPos))
            tempVal += 1ull << bitPos;

          if(registerStateSave[pointer] & (1ull << bitPos))
            tempVal += 1ull << bitPos;
        }

        uint64_t newStateVal = tempVal % bigModulo;

        stateRegisters[pointer] = newStateVal;

        tempVal = 0;
      }

      blockTrack = 0;
    }
  }

  /* Convert resulting state registers to hexadecimal notation */

  return hexDigest(stateRegisters, 4);
}

/*---------------------------------------------------------------------------*/
/*                       Begin Singularity-256 Section                       */
/*---------------------------------------------------------------------------*/
