#include "egihash/egihash.h"
#include <boost/thread/locks.hpp>
#include <boost/thread/mutex.hpp>
#include <memory>
#include <sstream>
#include <iomanip>
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>

#include "uint256.h"

using namespace std;

#ifdef __cplusplus
extern "C" {
#include "miner.h"
#endif

std::unique_ptr<egihash::dag_t> const & ActiveDAG(std::unique_ptr<egihash::dag_t> next_dag = std::unique_ptr<egihash::dag_t>());

std::string GetHex(const uint8_t* data, unsigned int size)
{
    char psz[size * 2 + 1];
    for (unsigned int i = 0; i < size; i++)
        sprintf(psz + i * 2, "%02x", data[size - i - 1]);
    return std::string(psz, psz + size * 2);
}


#pragma pack(push, 1)

//*
//*   The Keccak-256 hash of this structure is used as input for egihash
//*   It is a truncated block header with a deterministic encoding
//*   All integer values are little endian
//*   Hashes are the nul-terminated hex encoded representation as if ToString() was called

struct CBlockHeaderTruncatedLE
{
	int32_t nVersion;
	char hashPrevBlock[65];
	char hashMerkleRoot[65];
	uint32_t nTime;
	uint32_t nBits;
	uint32_t nHeight;

	CBlockHeaderTruncatedLE(const void* data)
	: nVersion(htole32(*reinterpret_cast<const int32_t*>(reinterpret_cast<const uint8_t*>(data) + 0)))
	, hashPrevBlock{0}
	, hashMerkleRoot{0}
	, nTime(htole32(*reinterpret_cast<const uint32_t*>(reinterpret_cast<const uint8_t*>(data) + 4 + 32 + 32 )))
	, nBits(htole32(*reinterpret_cast<const uint32_t*>(reinterpret_cast<const uint8_t*>(data) + 4 + 32 + 32 + 4 )))
	, nHeight(htole32(*reinterpret_cast<const uint32_t*>(reinterpret_cast<const uint8_t*>(data) + 4 + 32 + 32 + 4 + 4 )))
	{
		auto inputHashPrevBlock = reinterpret_cast<const uint8_t*>(data) + 4;
		auto prevHash = GetHex(inputHashPrevBlock, 32);
		memcpy(hashPrevBlock, prevHash.c_str(), (std::min)(prevHash.size(), sizeof(hashPrevBlock)));

		auto inputMerkleHashPrevBlock = reinterpret_cast<const uint8_t*>(data) + 36;
		auto merkleRoot = GetHex(inputMerkleHashPrevBlock, 32);
		memcpy(hashMerkleRoot, merkleRoot.c_str(), (std::min)(merkleRoot.size(), sizeof(hashMerkleRoot)));
/*
		uint32_t merkleRoot[8] = {0};
		for (int k=0; k < 8; k++)
			be32enc(&merkleRoot[k], ((uint32_t*)inputMerkleHashPrevBlock)[8 - k - 1]);
		auto merkleRootStr = GetHex((uint8_t*)merkleRoot, 32);
		memcpy(hashMerkleRoot, merkleRootStr.c_str(), (std::min)(merkleRootStr.size(), sizeof(hashMerkleRoot)));
*/



		/*for (int k=0; k < 8; k++)
				be32enc(((uint32_t*)hashPrevBlock) + k, ((uint32_t*)inputHashPrevBlock)[8 - k - 1]);*/


	}
};
#pragma pack(pop)




//
//extern void inkhash(void *state, const void *input)
//{
//    uint32_t _ALIGN(128) hash[16];
//    sph_shavite512_context ctx_shavite;
//
//    sph_shavite512_init(&ctx_shavite);
//    sph_shavite512 (&ctx_shavite, (const void*) input, 80);
//    sph_shavite512_close(&ctx_shavite, (void*) hash);
//
//    sph_shavite512_init(&ctx_shavite);
//    sph_shavite512(&ctx_shavite, (const void*) hash, 64);
//    sph_shavite512_close(&ctx_shavite, (void*) hash);
//
//    memcpy(state, hash, 32);
//}
//


void egihash_calc(void *output_hash, uint32_t height, uint32_t nonce, const void *input)
{
//    sph_keccak256_context ctx_keccak;
//    uint32_t hash[32];
//
//    sph_keccak256_init(&ctx_keccak);
//    sph_keccak256 (&ctx_keccak,input, 80);
//    sph_keccak256_close(&ctx_keccak, hash);
//
//	memcpy(state, hash, 32);



	CBlockHeaderTruncatedLE truncatedBlockHeader(input);
	egihash::h256_t headerHash(&truncatedBlockHeader, sizeof(truncatedBlockHeader));
	egihash::result_t ret;
	// if we have a DAG loaded, use it
	auto const & dag = ActiveDAG();

	if (dag && ((height / egihash::constants::EPOCH_LENGTH) == dag->epoch()))
	{
		ret = egihash::full::hash(*dag, headerHash, nonce);
	}
	else // otherwise all we can do is generate a light hash
	{
		// TODO: pre-load caches and seed hashes
		ret = egihash::light::hash(egihash::cache_t(height, egihash::get_seedhash(height)), headerHash, nonce);
	}

	//auto hashMix = uint256(std::vector<unsigned char>{ret.mixhash.b});
	//memcpy(output_hash, ret.value.b, sizeof(ret.value.b));

	memcpy(output_hash, ret.value.b, sizeof(ret.value.b));
	/*for (int k=0; k < 8; k++)
		be32enc(((uint32_t*)output_hash) + k, ((uint32_t*)ret.value.b)[8 - k - 1]);

	auto newHash = GetHex((uint8_t*)output_hash, 32);*/
	//cout << "NEW HASH: " << newHash << endl;

}




int scanhash_egihash(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done)
{
	uint32_t _ALIGN(128) hash[8];
	uint32_t _ALIGN(128) endiandata[21];
	uint32_t *pdata = work->data;
	uint32_t *ptarget = work->target;

	const uint32_t Htarg = ptarget[7];
	const uint32_t first_nonce = pdata[20];
	uint32_t nonce = first_nonce;
	volatile uint8_t *restart = &(work_restart[thr_id].restart);

	if (opt_benchmark)
		ptarget[7] = 0x0cff;

	for (int k=0; k < 20; k++)
		be32enc(&endiandata[k], pdata[k]);

	do {
		be32enc(&endiandata[20], nonce);
		//x11hash(hash, endiandata);
		egihash_calc(hash, work->height, nonce, endiandata);

		if (hash[7] <= Htarg && fulltest(hash, ptarget)) {
			work_set_target_ratio(work, hash);
			auto nonceForHash = be32dec(&nonce);
			pdata[20] = nonceForHash;
			*hashes_done = nonce - first_nonce;
			return 1;
		}
		nonce++;

	} while (nonce < max_nonce && !(*restart));

	pdata[20] = be32dec(&nonce);
	*hashes_done = nonce - first_nonce + 1;
	return 0;
}


std::unique_ptr<egihash::dag_t> const & ActiveDAG(std::unique_ptr<egihash::dag_t> next_dag/* = std::unique_ptr<egihash::dag_t>()*/)
{
    using namespace std;

    static boost::mutex m;
    boost::lock_guard<boost::mutex> lock(m);
    static unique_ptr<egihash::dag_t> active; // only keep one DAG in memory at once

    // if we have a next_dag swap it
    if (next_dag)
    {
        active.swap(next_dag);
    }

    // unload the previous dag
    if (next_dag)
    {
        next_dag->unload();
        next_dag.reset();
    }

    return active;
}


boost::filesystem::path GetDataDir()
{
    namespace fs = boost::filesystem;
	return fs::path("/media/ranjeet/F6306DE2306DAA77/Crypto/energi/regtest");
}

void InitDAG(egihash::progress_callback_type callback)
{
	using namespace egihash;

	auto const & dag = ActiveDAG();
	if (!dag)
	{
		auto const height = 0;// TODO (max)(GetHeight(), 0);
		auto const epoch = height / constants::EPOCH_LENGTH;
		auto const & seedhash = seedhash_to_filename(get_seedhash(height));
		stringstream ss;
		ss << hex << setw(4) << setfill('0') << epoch << "-" << seedhash.substr(0, 12) << ".dag";
		auto const epoch_file = GetDataDir() / "dag" / ss.str();

		printf("DAG file for epoch %u is \"%s\"", epoch, epoch_file.string().c_str());
		// try to load the DAG from disk
		try
		{
			unique_ptr<dag_t> new_dag(new dag_t(epoch_file.string(), callback));
			ActiveDAG(move(new_dag));
			printf("DAG file \"%s\" loaded successfully.", epoch_file.string().c_str());
			return;
		}
		catch (hash_exception const & e)
		{
			printf("DAG file \"%s\" not loaded, will be generated instead. Message: %s", epoch_file.string().c_str(), e.what());
		}

		// try to generate the DAG
		try
		{
			unique_ptr<dag_t> new_dag(new dag_t(height, callback));
			boost::filesystem::create_directories(epoch_file.parent_path());
			new_dag->save(epoch_file.string());
			ActiveDAG(move(new_dag));
			printf("DAG generated successfully. Saved to \"%s\".", epoch_file.string().c_str());
		}
		catch (hash_exception const & e)
		{
			printf("DAG for epoch %u could not be generated: %s", epoch, e.what());
		}
	}
	printf("DAG has been initialized already. Use ActiveDAG() to swap.");
}

bool InitEgiHashDag()
{
	// initialize the DAG
	InitDAG([](::std::size_t step, ::std::size_t max, int phase) -> bool
	{
			std::stringstream ss;
			ss << std::fixed << std::setprecision(2)
			<< static_cast<double>(step) / static_cast<double>(max) * 100.0 << "%"
			<< std::setfill(' ') << std::setw(80);

			auto progress_handler = [&](std::string const &msg)
			{
				std::cout << "\r" << msg;
			};

		switch(phase)
		{
			case egihash::cache_seeding:
					progress_handler("Seeding cache ... ");
				break;
			case egihash::cache_generation:
					progress_handler("Generating cache ... ");
				break;
			case egihash::cache_saving:
					progress_handler("Saving cache ... ");
				break;
			case egihash::cache_loading:
					progress_handler("Loading cache ... ");
				break;
			case egihash::dag_generation:
					progress_handler("Generating Dag ... ");
				break;
			case egihash::dag_saving:
					progress_handler("Saving Dag ... ");
				break;
			case egihash::dag_loading:
					progress_handler("Loading Dag ... ");
				break;
			default:
				break;
		}

		auto progress = ss.str();
		std::cout << progress << std::flush;

		return true;
	});

	return true;
}



#ifdef __cplusplus
}
#endif
