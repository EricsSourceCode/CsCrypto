// Copyright Eric Chauvin 2024.



// This is licensed under the GNU General
// Public License (GPL).  It is the
// same license that Linux has.
// https://www.gnu.org/licenses/gpl-3.0.html

// RFC 2104:
// HMAC: Keyed-Hashing for Message Authentication

// RFC 5869:
// HMAC-based Extract-and-Expand Key Derivation
// Function (HKDF)

// RFC 6234:
// US Secure Hash Algorithms (SHA and
// SHA-based HMAC and HKDF)


// FIPS 180-3

// FIPS 198-1



// Some Intel processors have SHA instructions.
// https://www.intel.com/content/www/us/en/
//           developer/articles/technical/
//           intel-sha-extensions.html
// They are SIMD extensions.




using System;



// namespace



public class Sha256
{
private MainData mData;
private Uint32Array intermediateHash;
private Uint32Array W;


private Sha256()
{
}



internal Sha256( MainData useMainData )
{
mData = useMainData;
intermediateHash = new Uint32Array();
W = new Uint32Array();
}



private static uint rotateR( uint x,
                             int howMuch )
{
return (x >> howMuch) |
       (x << (32 - howMuch));
}



// Not used.
//  static inline Uint32 rotateL( const Uint32 x,
//                        const Int32 howMuch )
//     {
//     return (x << howMuch) |
//            (x >> (32 - howMuch));
//     }


private static uint shaCh( uint x,
                           uint y,
                           uint z )
{
// Bitwise not ~.
return (x & y) ^ ((~x) & z);
}


/*
  static inline Uint32 shaMaj( const Uint32 x,
                               const Uint32 y,
                               const Uint32 z )
    {
    return (x & y) ^ (x & z) ^ (y & z);
    }

  // Notice how they did upper and lower case
  // names for the sigma #define statements.
  // That comes from the greek sigma symbol,
  // and there is a capital greek sigma and a
  // lower case sigma.
  // Upper case is B, lower case is S.
  // B for Big, S for Small.

  static inline Uint32 shaBSigma0( const Uint32 x )
    {
    return rotateR( x, 2 ) ^ rotateR( x, 13 ) ^
                             rotateR( x, 22 );
    }

  static inline Uint32 shaBSigma1( const Uint32 x )
    {
    return rotateR( x, 6 ) ^ rotateR( x, 11 ) ^
                             rotateR( x, 25 );
    }

  static inline Uint32 shaSSigma0( const Uint32 x )
    {
    return rotateR( x, 7 ) ^ rotateR( x, 18 ) ^
                             (x >> 3);
    }

  static inline Uint32 shaSSigma1( const Uint32 x )
    {
    return rotateR( x, 17 ) ^ rotateR( x, 19 ) ^
                             (x >> 10);
    }


  // For SHA 256.

  static constexpr Uint32 K[64] = {
      0x428a2f98, 0x71374491,
      0xb5c0fbcf, 0xe9b5dba5,
      0x3956c25b, 0x59f111f1,
      0x923f82a4, 0xab1c5ed5,
      0xd807aa98, 0x12835b01,
      0x243185be, 0x550c7dc3,
      0x72be5d74, 0x80deb1fe,
      0x9bdc06a7, 0xc19bf174,
      0xe49b69c1, 0xefbe4786,
      0x0fc19dc6, 0x240ca1cc,
      0x2de92c6f, 0x4a7484aa,
      0x5cb0a9dc, 0x76f988da,
      0x983e5152, 0xa831c66d,
      0xb00327c8, 0xbf597fc7,
      0xc6e00bf3, 0xd5a79147,
      0x06ca6351, 0x14292967,
      0x27b70a85, 0x2e1b2138,
      0x4d2c6dfc, 0x53380d13,
      0x650a7354, 0x766a0abb,
      0x81c2c92e, 0x92722c85,
      0xa2bfe8a1, 0xa81a664b,
      0xc24b8b70, 0xc76c51a3,
      0xd192e819, 0xd6990624,
      0xf40e3585, 0x106aa070,
      0x19a4c116, 0x1e376c08,
      0x2748774c, 0x34b0bcb5,
      0x391c0cb3, 0x4ed8aa4a,
      0x5b9cca4f, 0x682e6ff3,
      0x748f82ee, 0x78a5636f,
      0x84c87814, 0x8cc70208,
      0x90befffa, 0xa4506ceb,
      0xbef9a3f7, 0xc67178f2 };


    // 64 * 8 = 512 bits block size.
    // 256 bit hash length.

  public:
  static const Int32 BlockSize = 64; // Bytes.
  // 256 bits is 32 bytes.
  static const Int32 HashSize = 32;


// Test Vectors:
// For "abc"
// SHA-256
// ba7816bf 8f01cfea 414140de 5dae2223 b00361a3
   //             96177a9c b410ff61 f20015ad

// For the empty string.
// Length 0.
// If you test with an empty string then you are
// appending a 1 bit, and a length of zero.
// That is the 64 bytes.

// SHA-256
// e3b0c442 98fc1c14 9afbf4c8 996fb924
// 27ae41e4 649b934c a495991b 7852b855

// Input message:
// "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnl
//      mnomnopnopq"
// (length 448 bits).

// SHA-256
// 248d6a61 d20638b8 e5c02693 0c3e6039
// a33ce459 64ff2167 f6ecedd4 19db06c1

// A linux test:
// echo -n "abc" | sha256sum
// ba7816bf...



void Sha256::appendPadding( CharBuf& charBuf )
{
const Uint64 originalLength =
           Casting::i32ToU64( charBuf.getLast());

// StIO::printF( "originalLength: " );
// StIO::printFD( Casting::u64ToI32(
//               originalLength ));
// StIO::putS( "" );


// To restore it to the original length:
// CharBuf.truncateLast( Int32 setTo )

// Append that 1 bit.
charBuf.appendU8( 128 );

Int32 howBig = charBuf.getLast() % 64;

// StIO::printF( "howBig: " );
// StIO::printFD( howBig );
// StIO::putS( "" );


Int32 toAdd = 64 - howBig;

// You have to add the least number of zeros
// possible in order to make it zero mod
// 64 bytes.
// It already has seven zero bits after that
// 1 bit.

// if( toAdd == 64 )
  // toAdd = 0;

// StIO::printF( "toAdd at top: " );
// StIO::printFD( toAdd );
// StIO::putS( "" );

// For SHA 512 it's a 128 bit length value.
// So 16 bytes.

// 8 bytes for length.
toAdd -= 8;
if( toAdd < 0 )
  toAdd += 64;

// StIO::printF( "toAdd: " );
// StIO::printFD( toAdd );
// StIO::putS( "" );

// The spec says this has to be the smallest
// number of zeros to make it come to 64 bytes.
// 512 bits.

for( Int32 count = 0; count < toAdd; count++ )
  charBuf.appendU8( 0 );

Uint64 lengthInBits = originalLength * 8;
charBuf.appendU64( lengthInBits );

Int32 finalSize = charBuf.getLast();
if( (finalSize % 64) != 0 )
  throw "SHA padding finalSize is not right.";

}



void Sha256::init( void )
{
W.setSize( 64 );
intermediateHash.setSize( 8 );

// This is how they get set before the first
// block, but after the first block they are
// using the intermediate values from the
// previous block.  A chain of blocks.
// A block chain.

// Initial Hash Values: FIPS 180-3

intermediateHash.setVal( 0, 0x6A09E667 );
intermediateHash.setVal( 1, 0xBB67AE85 );
intermediateHash.setVal( 2, 0x3C6EF372 );
intermediateHash.setVal( 3, 0xA54FF53A );
intermediateHash.setVal( 4, 0x510E527F );
intermediateHash.setVal( 5, 0x9B05688C );
intermediateHash.setVal( 6, 0x1F83D9AB );
intermediateHash.setVal( 7, 0x5BE0CD19 );
}



void Sha256::processAllBlocks(
                        const CharBuf& charBuf )
{
CharBuf toHashBuf;
toHashBuf.copy( charBuf );

appendPadding( toHashBuf );
init();

Int32 max = toHashBuf.getLast();
if( (max % 64) != 0 )
  throw "processAllBlocks (max % 64) != 0";

for( Int32 where = 0; where < max; where += 64 )
  {
  // StIO::putS( "Processing message block." );
  processMessageBlock( toHashBuf, where );
  }

// StIO::putS( "Hash at end:" );
// showHash();

// StIO::putS( "Finished the block chain." );
}



void Sha256::showHash( void )
{
CharBuf hashBuf;
getHash( hashBuf );

const Int32 maxBytes = hashBuf.getLast();
for( Int32 count = 0; count < maxBytes; count++ )
  {
  Uint8 oneByte = hashBuf.getU8( count );
  char leftC = ByteHex::getLeftChar( oneByte );
  StIO::putChar( leftC );
  char rightC = ByteHex::getRightChar( oneByte );
  StIO::putChar( rightC );
  StIO::putChar( ' ' );
  }

StIO::putChar( '\n' );
}



// Get the Message Digest as a series of bytes.
void Sha256::getHash( CharBuf& charBuf )
{
charBuf.clear();

// The hash length is 8 times 32 bits.

for( Int32 count = 0; count < 8; count++ )
  {
  // Big endian.
  Uint32 toSet = intermediateHash.getVal( count );
  charBuf.appendU32( toSet );
  }
}



void Sha256::processMessageBlock(
                  const CharBuf& charBuf,
                  const Int32 where )
{
const Int32 last = charBuf.getLast();
if( (where + 63) >= last )
  throw "Sha256.processMessageBlock( last.";

for( Int32 count = 0; count < 16; count++ )
  {
  W.setVal( count, charBuf.getU32(
                       where + (count * 4) ));
  }

for( Int32 count = 16; count < 64; count++ )
  {
  Uint32 toSet1 = shaSSigma1( W.getVal( count - 2 ));
  Uint32 toSet2 = W.getVal( count - 7 );
  Uint32 toSet3 = shaSSigma0( W.getVal(
                                     count - 15 ));
  Uint32 toSet4 = W.getVal( count - 16 );

  Uint32 toSet = toSet1 + toSet2 + toSet3 +
                                   toSet4;

  W.setVal( count, toSet );
  }

Uint32 A = intermediateHash.getVal( 0 );
Uint32 B = intermediateHash.getVal( 1 );
Uint32 C = intermediateHash.getVal( 2 );
Uint32 D = intermediateHash.getVal( 3 );
Uint32 E = intermediateHash.getVal( 4 );
Uint32 F = intermediateHash.getVal( 5 );
Uint32 G = intermediateHash.getVal( 6 );
Uint32 H = intermediateHash.getVal( 7 );

for( Int32 t = 0; t < 64; t++ )
  {
  Uint32 temp1 = H + shaBSigma1( E ) +
         shaCh( E, F, G ) + K[t] +
         W.getVal( t );

  Uint32 temp2 = shaBSigma0( A ) +
                            shaMaj( A, B, C );

  H = G;
  G = F;
  F = E;
  E = D + temp1;
  D = C;
  C = B;
  B = A;
  A = temp1 + temp2;
  }

// Intermediate_Hash[0] += A;

intermediateHash.setVal( 0,
           intermediateHash.getVal( 0 ) + A );

intermediateHash.setVal( 1,
           intermediateHash.getVal( 1 ) + B );

intermediateHash.setVal( 2,
           intermediateHash.getVal( 2 ) + C );

intermediateHash.setVal( 3,
           intermediateHash.getVal( 3 ) + D );

intermediateHash.setVal( 4,
           intermediateHash.getVal( 4 ) + E );

intermediateHash.setVal( 5,
           intermediateHash.getVal( 5 ) + F );

intermediateHash.setVal( 6,
           intermediateHash.getVal( 6 ) + G );

intermediateHash.setVal( 7,
           intermediateHash.getVal( 7 ) + H );

}




void Sha256::hMac( CharBuf& result,
                   const CharBuf& key,
                   const CharBuf& message )
{
// 64 * 8 = 512 bits block size.
// 256 bit hash length.

// RFC 2104 says:
// "We denote by B the byte-length of such
// blocks ... and by L the byte-length of
// hash outputs."

const Int32 B = 64;
const Int32 L = 32;

CharBuf innerKey;
CharBuf outerKey;

innerKey.copy( key );

Int32 lastKey = innerKey.getLast();
if( lastKey > B )
  {
  processAllBlocks( innerKey );
  getHash( innerKey );
  }

lastKey = innerKey.getLast();

if( lastKey < B )
  {
  const Int32 howMany = B - lastKey;
  for( Int32 count = 0; count < howMany; count++ )
    innerKey.appendU8( 0 );

  if( innerKey.getLast() != B )
    throw "Inner key padding was bad.";

  }

outerKey.copy( innerKey );

// ipad
for( Int32 count = 0; count < B; count++ )
  {
  Uint8 xByte = innerKey.getU8( count ) xor 0x36;
  innerKey.setU8( count, xByte );
  }

CharBuf innerHash;
innerHash.copy( innerKey );
innerHash.appendCharBuf( message );

processAllBlocks( innerHash );
getHash( innerHash );

if( innerHash.getLast() != L )
  throw "The hash length is not right.";

// opad
for( Int32 count = 0; count < B; count++ )
  {
  Uint8 xByte = outerKey.getU8( count ) xor 0x5C;
  outerKey.setU8( count, xByte );
  }

CharBuf outerHash;
outerHash.copy( outerKey );
outerHash.appendCharBuf( innerHash );

processAllBlocks( outerHash );

// Hash( K XOR opad, H( K XOR ipad, text ))

getHash( result );

// StIO::putS( "HMAC result: " );
// result.showHex();
// StIO::putLF();

// Test vectors are in RFC 8448.

// This test vector came from the HMAC
// article on Wikipedia.
// HMAC_SHA256( "key", "The quick brown fox
//  jumps over the lazy dog") =
// f7bc83f430538424b13298e6aa6fb143ef4d5
// 9a14946175997479dbc2d1a3cd8
}



void Sha256::makeHash( CharBuf& result,
                       const CharBuf& message )
{
processAllBlocks( message );
getHash( result );

// StIO::putS( "Hash for makeHash():" );
// showHash();
// StIO::putS( "\n\n" );
}

*/



} // Class
