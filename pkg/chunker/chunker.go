package chunker

import (
	"fmt"
	"io"
	"os"
)

// DefaultChunkSize defines the target byte size for each file slice.
// In AuraCloud, we use a 2MB chunk size (2 * 1024 * 1024 bytes).
// Fixed-size chunking simplifies memory allocation, buffer management,
// and network transfer units across peer nodes in the storage mesh.
const DefaultChunkSize int64 = 2 * 1024 * 1024 // 2 Megabytes

// Chunk represents a discrete, ordered segment of a file.
// Architectural Concept:
// Files are not stored whole in P2P backup systems. Splitting files into chunks
// allows content addressing (hashing each chunk), deduplication across users,
// and distributed storage across multiple peer nodes.
type Chunk struct {
	Index int    // Zero-indexed sequence position of the chunk in the original file
	Data  []byte // Raw byte slice holding the chunk's payload
	Size  int64  // Actual byte length of Data (<= DefaultChunkSize)
}

// ChunkFile opens a file at the given path and reads it sequentially into fixed-size chunks.
//
// Parameters:
//   - filePath: Path to the target file on the local filesystem.
//   - chunkSize: The max size (in bytes) of each chunk. If <= 0, DefaultChunkSize is used.
//
// Returns:
//   - []Chunk: A ordered slice of Chunk structs representing the full file.
//   - error: Any filesystem or I/O read error encountered during chunking.
func ChunkFile(filePath string, chunkSize int64) ([]Chunk, error) {
	// Fall back to default chunk size if non-positive value provided
	if chunkSize <= 0 {
		chunkSize = DefaultChunkSize
	}

	// Open the file in read-only mode using standard OS utilities.
	// os.Open returns a *os.File handle which implements the io.Reader interface.
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("chunker: failed to open file %s: %w", filePath, err)
	}
	// Ensure file handle is closed when function returns, preventing resource leaks.
	defer file.Close()

	// Delegate memory reading to ChunkReader for testability and flexibility.
	return ChunkReader(file, chunkSize)
}

// ChunkReader reads an io.Reader stream until EOF and slices it into Chunks.
// By accepting an io.Reader interface instead of a file path directly, this function
// can chunk file streams, network streams, or in-memory byte buffers seamlessly.
func ChunkReader(r io.Reader, chunkSize int64) ([]Chunk, error) {
	if chunkSize <= 0 {
		chunkSize = DefaultChunkSize
	}

	var chunks []Chunk
	index := 0

	for {
		// Allocate a temporary buffer of exact chunkSize for reading.
		// WHY: Pre-allocating the slice guarantees we have memory ready for the reader stream.
		buf := make([]byte, chunkSize)

		// io.ReadFull reads exactly len(buf) bytes from r into buf.
		// It returns io.ErrUnexpectedEOF if EOF is encountered before filling buf.
		// It returns io.EOF if zero bytes were read because we reached the end of stream.
		n, err := io.ReadFull(r, buf)

		if err == io.EOF {
			// Clean end of file before reading any bytes in this iteration.
			break
		}

		if err != nil && err != io.ErrUnexpectedEOF {
			// A true I/O error occurred (e.g., read permission issue, corrupted media read).
			return nil, fmt.Errorf("chunker: read error at index %d: %w", index, err)
		}

		// If n > 0, we read some bytes (either a full chunk or a final partial chunk).
		// We slice buf[:n] so we don't include uninitialized zero-bytes from trailing buffer space.
		chunkData := make([]byte, n)
		copy(chunkData, buf[:n])

		chunk := Chunk{
			Index: index,
			Data:  chunkData,
			Size:  int64(n),
		}

		chunks = append(chunks, chunk)
		index++

		// If err was io.ErrUnexpectedEOF, we reached the end of the input stream on a final partial chunk.
		if err == io.ErrUnexpectedEOF {
			break
		}
	}

	return chunks, nil
}
