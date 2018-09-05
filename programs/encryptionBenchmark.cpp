#include <iostream>
#include <chrono>
#include <fse.h>
#include <memory>
#include <iomanip>
#include <vector>
#include <numeric>
#include <algorithm>
#include <encryptor.h>
#include <string.h>

using std::string;
using std::chrono::duration_cast;
using std::chrono::milliseconds;
using std::cout;
using std::endl;

double toMBps(size_t bytes, double operationTimeMS)
{
    static const size_t MBSize = 1024 * 1024;
    return static_cast<double>(bytes) / (operationTimeMS * 0.001) / MBSize;
}

size_t read_file(unsigned char* buffer, size_t BUFFER_SIZE, const char* FILE_NAME)
{
    FILE *f;
    size_t read_bytes = 0;

    f = fopen(FILE_NAME, "rb");
    if (f)
        read_bytes = fread(buffer, sizeof(unsigned char), BUFFER_SIZE, f);
    else
    {
        printf("Error when opening the file: %s\n", FILE_NAME);
        return 0;
    }

    fclose(f);

    // for AES testing, its required that buffer is divisible by block size
    return read_bytes - (read_bytes % 16);
}


class Benchmark
{
public:
    static const size_t BUFFER_SIZE = 2'000'000;

    void run(const string& fileName)
    {
        size_t read_bytes;
        std::vector<int64_t> compressionTimes;
        std::vector<int64_t> decompressionTimes;

        size_t compression_result;

        for (size_t i = 0; i < 1; i++)
        {
            // read sample data
            auto buffer = std::make_unique<unsigned char[]>(BUFFER_SIZE);

            read_bytes = read_file(buffer.get(), BUFFER_SIZE, fileName.c_str());

            auto compressed_buffer = std::make_unique<unsigned char[]>(BUFFER_SIZE);
            // compress
            auto beginCompression = std::chrono::high_resolution_clock::now();

            compression_result = compress(compressed_buffer.get(), BUFFER_SIZE, buffer.get(), read_bytes);

            auto endCompression = std::chrono::high_resolution_clock::now();

            auto decompressed_buffer = std::make_unique<unsigned char[]>(BUFFER_SIZE);
            // decompress
            auto beginDecompression = std::chrono::high_resolution_clock::now();

            auto decompress_result = decompress(decompressed_buffer.get(), BUFFER_SIZE, compressed_buffer.get(), compression_result);

            auto endDecompression = std::chrono::high_resolution_clock::now();

            if (!is_operation_successful(decompress_result))
                throw std::runtime_error("Operation failed");

            // calculate time passed
            auto compressionTime = duration_cast<milliseconds>(endCompression - beginCompression).count();
            auto decompressionTime = duration_cast<milliseconds>(endDecompression - beginDecompression).count();

            compressionTimes.push_back(compressionTime);
            decompressionTimes.push_back(decompressionTime);
        }

        auto avgCompressionTime = std::accumulate(compressionTimes.begin(), compressionTimes.end(), 0.0) / compressionTimes.size();
        auto avgDecompressionTime = std::accumulate(decompressionTimes.begin(), decompressionTimes.end(), 0.0) / decompressionTimes.size();

        cout << "Report for: " << getTestName() << " file name:" << fileName << endl;
        cout << "original size: " << read_bytes << std::endl;
        cout << "compressed size: " << compression_result << std::endl;
        cout << "Average compression speed MB/s: " << toMBps(read_bytes, avgCompressionTime)
//             << " min: "
//             << toMBps(read_bytes, *std::max_element(compressionTimes.begin(), compressionTimes.end()))
//             << " max:"
//             << toMBps(read_bytes, *std::min_element(compressionTimes.begin(), compressionTimes.end()))
             << endl;

        cout << "Average decompression speed MB/s: " << toMBps(read_bytes, avgDecompressionTime)
//             << " min: "
//             << toMBps(read_bytes, *std::max_element(decompressionTimes.begin(), decompressionTimes.end()))
//             << " max:"
//             << toMBps(read_bytes, *std::min_element(decompressionTimes.begin(), decompressionTimes.end()))
             << endl;

        cout << endl;
    }

protected:
    virtual std::string getTestName() = 0;
    virtual size_t compress(void* dst, size_t dstCapacity, const void* src, size_t srcSize) = 0;
    virtual size_t decompress(void* dst, size_t dstCapacity, const void* cSrc, size_t cSrcSize) = 0;
};

class NoEncryption : public Benchmark
{
protected:
    std::string getTestName() override
    {
        return "No encryption";
    }

    size_t compress(void* dst, size_t dstCapacity, const void* src, size_t srcSize) override
    {
       return FSE_compress(dst, dstCapacity, src, srcSize, nullptr);
    }

    size_t decompress(void* dst, size_t dstCapacity, const void* cSrc, size_t cSrcSize) override
    {
        return FSE_decompress(dst, dstCapacity, cSrc, cSrcSize, nullptr);
    }
};


class Encryption : public Benchmark
{
    unsigned char KEY[32] = {
            1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8
    };

    unsigned char IV[16] = {
            1, 6, 3, 4, 7, 6, 7, 8, 1, 3, 5, 4, 5, 6, 7, 8
    };

public:
    Encryption()
    : ctx(std::make_unique<EncryptionCtx>())
    {
       ctx->iv = IV;
       ctx->key = KEY;
       ctx->shuffle_seed = KEY;
    }

protected:

    std::unique_ptr<EncryptionCtx> ctx;
};


class MyEncryption : public Encryption
{
protected:
    std::string getTestName() override
    {
        return "MyEncryption";
    }

    size_t compress(void* dst, size_t dstCapacity, const void* src, size_t srcSize) override
    {
        return FSE_compress(dst, dstCapacity, src, srcSize, ctx.get());
    }

    size_t decompress(void* dst, size_t dstCapacity, const void* cSrc, size_t cSrcSize) override
    {
        return FSE_decompress(dst, dstCapacity, cSrc, cSrcSize, ctx.get());
    }
};

class AESEncryption : public Encryption
{
protected:
    std::string getTestName() override
    {
        return "AESEncryption";
    }

    size_t compress(void* dst, size_t dstCapacity, const void* src, size_t srcSize) override
    {
        auto size = FSE_compress(dst, dstCapacity, src, srcSize, nullptr);

        auto tmp_mem = std::make_unique<unsigned char[]>(BUFFER_SIZE);
        memcpy(tmp_mem.get(), dst, size);

        aes_encrypt((unsigned char*)dst, (const unsigned char*)tmp_mem.get(), srcSize, ctx->key, ctx->iv);
        return size;
    }

    size_t decompress(void* dst, size_t dstCapacity, const void* cSrc, size_t cSrcSize) override
    {
        auto tmp_mem = std::make_unique<unsigned char[]>(BUFFER_SIZE);
        memcpy(tmp_mem.get(), cSrc, cSrcSize);

        aes_decrypt((unsigned char*) cSrc, (const unsigned char*) tmp_mem.get(), cSrcSize, ctx->key, ctx->iv);
        return FSE_decompress(dst, dstCapacity, cSrc, cSrcSize, nullptr);
    }
};


int main() {
    std::vector<std::string> fileNames = {
            "tests/proba_70.bin",
            "tests/proba_30.bin",
            "tests/proba_01.bin"
    };

    {
        auto encryptionBenchmark = std::make_unique<MyEncryption>();
        for (const auto &fileName : fileNames)
            encryptionBenchmark->run(fileName);
    }

    std::cout << "#############################################" << std::endl;

    {
        auto noEncryptionBenchmark = std::make_unique<NoEncryption>();
        for (const auto& fileName : fileNames) {
            noEncryptionBenchmark->run(fileName);
        }
    }

    std::cout << "#############################################" << std::endl;

    {
        auto noEncryptionBenchmark = std::make_unique<AESEncryption>();
        for (const auto& fileName : fileNames) {
            noEncryptionBenchmark->run(fileName);
        }
    }

    return 0;
}
