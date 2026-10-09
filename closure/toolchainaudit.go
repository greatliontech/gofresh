package closure

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/greatliontech/gofresh/gotool"
)

// auditedToolchainSources is the one toolchain-source listing of this
// package: every row keyed by the CONTENT the admissions were audited
// over — one digest per audited surface package over the files the
// build selects for it (toolchainsource.go derives the surface and
// the digests). The
// standard-library admissions (the audited-pure package set, the
// class-B pure operations, the audited sync/pool/reflect symbols, the
// atomic transparency, the harness logging and subtest-driver
// channels, the writer-sink admission, the linkname-target floor) are
// properties of SPECIFIC toolchain source, audited walk by walk, and no
// other source inherits a proof — exactly the discipline the
// version-pinned module audits and the property-harness audit already
// follow. A toolchain whose surface carries a digest no row's chain
// lists keeps every symbol's ordinary fail-closed classification:
// proofs refuse loudly, naming the keys that moved off the closest
// row, until their delta is walked against the admission bar and the
// walk's digests listed here (TestAuditedToolchainCoversRunningToolchain
// is the canary that makes a toolchain move fail as one named test,
// printing the row to list, instead of a scatter of fixture flips). A
// toolchain whose every digest one chain lists is audited whatever its
// version string says — a rebuild of identical source, an experiment
// that selects no different file, a vendor flavor whose patches are
// tag-gated out of the selection, a point release off the audited
// surface — and the label on a row is the version the row was listed
// over, documentary.
//
// The surface is the audited packages and every standard package they
// reach through imports, the runtime included — the delegates an
// admitted body's behaviour rests on at any depth, and the runtime
// every admission compiles against, where a vendor fork's hooks live
// (the godst build patches runtime/chan.go and adds runtime/dst_*.go)
// — so a change anywhere beneath an admission moves its key; a row
// therefore
// asserts that the admissions hold over THAT toolchain's whole
// surface, which is what the walks judged (by reading the audited
// packages and the delegates their bodies name; the deeper packages
// ride the judgment as the toolchain the walk ran over). A row's keys
// are judged as one chain: a complete row lists the whole surface, a
// delta row the keys that differ from its base's chain, and the
// admission needs one chain to list every running key — a tree mixing
// two listed releases' packages is no listed toolchain, one release's
// race runtime over another's files included — a selection's row (the
// race seams, the platform splits, the cgo stubs) is a delta over its
// own toolchain's default row and never admits over another's. The
// toolchain's code generation — the compiler's intrinsics (sync/atomic
// and math/bits compile to instructions, not to their keyed assembly)
// and instrumentation passes, the linker — is outside the key by
// premise: the admissions are judged over source semantics as the
// language specifies them, and a miscompiling toolchain invalidates
// every proof, not the admissions alone. The audit record per listed
// row lives in the
// commit that lists it (recover with `git log --all --
// closure/toolchainaudit.go`; the version-keyed listing this table
// replaced, with every walk's record from go1.27.0 to
// go1.27.1-dst.13, is in that history).
//
// A selection is part of the key exactly as far as it selects bytes:
// the digests are taken over the files the build selects under the
// analysis' platform, cgo setting, tags and experiments, so a tag no
// surface file is constrained on or an experiment that swaps none
// yields the listed digests, while a selection that selects other
// bytes — a vendor fork's hook tag selecting its live hook bodies, a
// tag selecting a surface package's constrained files, another
// platform's split files, cgo off — refuses until its own row is
// listed from a host that can list it (the canary prints the row).
//
// The rows below are computed on their listing host (linux/amd64,
// cgo on); the godst series' other builds (go1.27.0-dst.10–15, the
// nodwarf5 flavors) are unlisted until a host carrying them lists a
// row — their hooks are compiled dead code behind constants and
// identity stubs, so their source differs from stock and the content
// key cannot see that the hooks are dead.
// listedSelections are the build selections every listing host lists
// rows for, beside its own default: the race selection (the race
// seams), the platforms the fleet analyzes for from a host of another
// platform, and cgo off (the default of every host without a C
// compiler) — each a delta row over the host's default row, bound to
// that toolchain's chain, listable from any host carrying the
// toolchain because every
// platform's files are in the one GOROOT; the audited packages' split
// files were read whole by the walks, and the deeper packages ride the
// toolchain judgment as they do under the default selection. The
// canary runs each; an analysis under a selection no row covers
// refuses until a host lists it.
var listedSelections = []listedSelection{
	{},
	{Suffix: " race", Flags: []string{"-race"}},
	{Suffix: " plan9/amd64", Env: []string{"GOOS=plan9", "GOARCH=amd64"}},
	{Suffix: " cgo0", Env: []string{"CGO_ENABLED=0"}},
	{Suffix: " dst", Flags: []string{"-tags", "dst"}, Since: "go1.27.2-dst.15"},
	{Suffix: " dst race", Flags: []string{"-tags", "dst", "-race"}, Since: "go1.27.2-dst.15"},
}

// listedSelection is one selection the listing hosts list: the label
// suffix after the version and the environment settings and build
// flags that select it; its row is a delta over the host's default
// row.
type listedSelection struct {
	Suffix string
	Env    []string
	Flags  []string
	// Since bounds the canary's obligation on old godst builds whose
	// harness did not propagate failed test-log writes. It never grants
	// admission: the source digests decide that independently.
	Since string
}

func (s listedSelection) demandedOf(version string) bool {
	if s.Since == "" {
		return true
	}
	have, haveOK := godstCounter(version)
	first, firstOK := godstCounter(s.Since)
	return !haveOK || !firstOK || have >= first
}

func godstCounter(version string) (int, bool) {
	base, counter, found := strings.Cut(version, "-dst.")
	if !found || gotool.LanguageSeries(base) == "" {
		return 0, false
	}
	n, err := strconv.Atoi(counter)
	return n, err == nil && n > 0
}

var auditedToolchainSources = []toolchainSourceRow{
	// go1.27.1-dst.13 (the listing host's godst build): the whole
	// surface under the default selection on linux/amd64 with cgo —
	// stock go1.27.1's source (the walks recorded under the version
	// listing, in history) with the fork's hooks compiled dead behind
	// constants and identity stubs in the runtime, its maps delegate,
	// sync, time, testing, os, net's internal/sync delegate,
	// crypto/rand's sysrand delegate, and syscall's prlimit file
	// carrying its stamp — the ten keys the stock row below re-lists.
	// Every other key is stock's, byte for byte.
	{
		Label: "go1.27.1-dst.13",
		Packages: map[string]string{
			"bufio":                                      "2166e5c1a6339c54069a3294d3781576fe41415c507790f19f779f50da0e6dec",
			"bytes":                                      "1c065a2114cf9ca4ca3be1f732691ba9d98aeab6235592e8d1b1b395a7bf313e",
			"cmp":                                        "3c47a51610de7894e57c5ed31f3ac9f45d3f633610f0d90b1ace76270a3eafe4",
			"compress/flate":                             "9ce5da2029a000777ad9f0f73cd16e2aee5ecf87053cafa14fe287fed4b57bae",
			"compress/gzip":                              "857362b8cfaef8d480676642bf8e16f3f5cc854b7f4743a27850b7ee87d5c1a4",
			"container/heap":                             "b09282b8d7b856882ab8f6c795541fcce3d13251d5b40b91bfd9a58d3db9fa52",
			"container/list":                             "d8a43b59d767b0f57286e92ef6a64c3d862b1e17b071ceb9c46df37e6869369c",
			"container/ring":                             "5cec1ba22763057053693c8d0152d90b5d26ecb0d7d7dca435f2c921d452c791",
			"context":                                    "67216404fb72057e1011600593ed6b444a2a50d49f2059f89fc5e7447287992a",
			"crypto":                                     "92cf63073df15ba679a086888b0ef244e5fbb8d1d7a1823853d921912d40d63e",
			"crypto/aes":                                 "c7958321c20a5658d6ff311bcfcf87358882a7a3317aece631252c56c3d6aec6",
			"crypto/cipher":                              "ebc98fd8a66e4107b4c2115900ccbb22c77674bbc1948760327bd1dc2bad032c",
			"crypto/des":                                 "d6183986532f9039a5362ddf9397c6ef87a8bd889c9937038ed3367da1f7a775",
			"crypto/dsa":                                 "a518ab097ee348089eb003041b1ddcf6b2caae850383cce55a34f64a6e7edee0",
			"crypto/ecdh":                                "16c46cd2d792962f770b61070efaa2fa3806ce4806b9b4a340a85670cdbc4210",
			"crypto/ecdsa":                               "e4774c812f16943a92850c588c506dee45e7ac1eed0a53e0075f2c8eca188380",
			"crypto/ed25519":                             "cda3318e1f282838e52acf9a9b7f8f3b09b5175785d3174da996d2d98af8af27",
			"crypto/elliptic":                            "6e446f89cdbb171d64c37f840a686c7e8234e6b1777db7e33393c675c7146960",
			"crypto/fips140":                             "4de5695dd6649c99573b6b2d3b5b70ed768d823e3b959036a22b69456857d2d2",
			"crypto/hkdf":                                "3c5834b9f9fb940a688061162c8b082694517734820e6e96c693257266e5787d",
			"crypto/hmac":                                "253b324375cb967a5c8cf22db932da470760e7445468bc73739f69d45eaa535c",
			"crypto/hpke":                                "afbde8e26c2b9fa0026e540d21a48c8b4f115a4d25ae958acb2547587275ba6d",
			"crypto/internal/boring":                     "4122e7721864561e37af04a13d4d3b989fd688d8be4982ba533cfc40f72797c7",
			"crypto/internal/boring/bbig":                "67ccc4a3083ea88407dca4eadf4c65dc9a1d5c6883d2a97af7bae6a865b4f79f",
			"crypto/internal/boring/sig":                 "d215e8a590972ad38d5ed327d8ee7da786291f187927746dbf43c539346bb57b",
			"crypto/internal/constanttime":               "d3e5864c1a6ae2b4554859785fc096ffb047ec64954f1f7d338b69916e1a41c0",
			"crypto/internal/entropy/v1.0.0":             "8b7844dda05ad466775bcedc6045ffe9c58ce93137fe2d36f6c8663845c2db97",
			"crypto/internal/fips140":                    "0ad2945f394a3c861b3768340ec9382e942c129963fd15aa1558a0558d5ed0e6",
			"crypto/internal/fips140/aes":                "d7ae4014da2d08d26e2e7dda00546a2593b4fe72eeb897ff8a73ab9e9041f77e",
			"crypto/internal/fips140/aes/gcm":            "b3cab1f4b6e96b377c3bb971dc2c91539aad0e178b7980832dfd619b698cfa46",
			"crypto/internal/fips140/alias":              "226ad5b2db40abe53382741a2915cca79a34e88aae551c3d2e7c28dc6f22d747",
			"crypto/internal/fips140/bigmod":             "95c621c72288a1a53359cde556aa98f1d3a7598f9c3d157693a5a9c11d141939",
			"crypto/internal/fips140/check":              "b4b979ec4ce55688883fc85c56e0fe74463e7d86462001567352dbc278d2dcfa",
			"crypto/internal/fips140/drbg":               "f16c935f1edaa1a41fdd779bf5c4f23010a6868b37ca64f7ab30351236dcc836",
			"crypto/internal/fips140/ecdh":               "dc5106360c3592cdec5d945a0cf2ce53fc46d45de67a9c6c0f1aeb78bc9b6767",
			"crypto/internal/fips140/ecdsa":              "5b8a329a03acd2e0063f1bc5a90eec3f5d7597577dfb7c60c738184eadfc72b3",
			"crypto/internal/fips140/ed25519":            "4400ab6877c56e553676baba215aaed8924ab5c2bf33175fd5eeb7a23cb5e771",
			"crypto/internal/fips140/edwards25519":       "a89335453d19e997ac703610dbb9e6c89aca96f65ede8677854c0cb21cbf6cfb",
			"crypto/internal/fips140/edwards25519/field": "99ca5c95f982d5f1aecefd048cf9094b72dfe3379a1b434e50eb6cdf4d197f62",
			"crypto/internal/fips140/hkdf":               "10debcadd487e9641ff7c222255042abcc49090e09794cd5c757a6ad825509ac",
			"crypto/internal/fips140/hmac":               "40560ae789f63d12313743436bf438f26e97127aceb5fc10dc136692909c02e6",
			"crypto/internal/fips140/mldsa":              "71ec6b92e431460687112cc4ba0ac99b552f7590b61e1cd02fa117de39d183eb",
			"crypto/internal/fips140/mlkem":              "66dd5d9c831181ae048834a75dcd0847610eba4317f36a469159c32e47f4587f",
			"crypto/internal/fips140/nistec":             "cf68175b222f64b6568f10ed4194b807bc05aba924c9dc0755c8500541552d22",
			"crypto/internal/fips140/nistec/fiat":        "7891042501946f433fa357bfd1dbb7a56244630f1e2afcca4334e336a817380b",
			"crypto/internal/fips140/rsa":                "00b71ffc592c2bdf3543569de04d8a05e3cb57c8253398b6c0f36c9b9f01d7a4",
			"crypto/internal/fips140/sha256":             "540d57b3ff54e3261d74410de15b33be9318fb3b767e97cbc115ab4bb087f1e8",
			"crypto/internal/fips140/sha3":               "fac94b7a1fbcd6c53b02a5379f72d9ca32f149ccc32d6d41543b159a1466d333",
			"crypto/internal/fips140/sha512":             "8f49f0e5ca7c6802ed3ee2cbe91019bc104afe59dc69ddc8612c0b438772ec51",
			"crypto/internal/fips140/subtle":             "4efd3916788c429dcbb16dbea80a103005e59939073b263844d8022d4142c28d",
			"crypto/internal/fips140/tls12":              "c3ccbb5e2efacc7cd7923223ee8e355c0aeee21873ddcd3721b72d4a7c866466",
			"crypto/internal/fips140/tls13":              "e634e63a615d62b8d0dfd607af84ad42b6ac8f9119bd207ce0901306ac622556",
			"crypto/internal/fips140cache":               "a78105060b157c2f402e105539b173191b84f0e53752f1d47924ebbcea52355c",
			"crypto/internal/fips140deps/byteorder":      "ed2f6c966339ce4bc0a176289bba22964491f1a382e14def88deb7890e2ab0fe",
			"crypto/internal/fips140deps/cpu":            "4148bc2a7817ca1461247c8d33b42f5da2b961436717f96a6e8ed45b055accce",
			"crypto/internal/fips140deps/godebug":        "38e41277942b687b0a38bfd6153533aae8d574581e43311bb9f9b1fe992c95b2",
			"crypto/internal/fips140deps/time":           "02ad11ab171f70311966e6bb838e9b2208df49986fff85bfe894365785c18e84",
			"crypto/internal/fips140hash":                "2eca55f972bf8d5d820e6aef8f6a6c7c19b0c6b8e83b89eba7dca03bad81c639",
			"crypto/internal/fips140only":                "935a49ab0769237176347ac707f99ddb9c60a8dd5ed4564bb607a60fbdffd279",
			"crypto/internal/impl":                       "691ea585795d107a41e58c5f297b6f2ce156aca7e123f6e24b3a002e237d8380",
			"crypto/internal/rand":                       "36e849e82f779cefca9fea4d4b2f1f4e5f4a407b6a73b168bae4e886f535a3ab",
			"crypto/internal/randutil":                   "52fd0b5cc7abc379e015a6fbaf6f99ee4daad4b1f4880c57de974fa002bfc260",
			"crypto/internal/sysrand":                    "dd638b8484a36ebd786ff0cb7b8abe50d515d7e066eb4f5085a68bbb4b954ae4",
			"crypto/md5":                                 "0658d46a6e86a33f0c073747bccd0fa179bc8635ae639b71981df136ff8b7af9",
			"crypto/mldsa":                               "78a8d2c71a37e63a0f1ea2b89a488e6eae523a5aac384a5c9a40f989fb7f532b",
			"crypto/mlkem":                               "5016fd8029c38b8ac80c4ee7b2bae4f5c6572c7f774ccea656fe5bc994995e8b",
			"crypto/rand":                                "95b29578370eaa72be7aa082180839717e483f228655e2d506bbbaadd8ab2f25",
			"crypto/rc4":                                 "5b7697f888f8055cf28f4da92a4ab9f673829c2ba09735467b59e57e9832368d",
			"crypto/rsa":                                 "38a2fb4f258d9240acf85b1246139327eb839f0c876cd40430ded2c6560afa3b",
			"crypto/sha1":                                "f3dadc129ecc735a257a52562a3eb637ff5ad50cd04a00db00b9a63265faab15",
			"crypto/sha256":                              "b14bf85424a7f28cde525819041b52ab28015435ade20fe60078dec2cf724e9a",
			"crypto/sha3":                                "5b6bfcbb1d605c6cba4ba64bb2af9c64e280709d86b797e5c1984e75ffe89d08",
			"crypto/sha512":                              "4413fe40ce92d247c67ef4783f4446413cb78b016de71820633be1e3b9bf5a68",
			"crypto/subtle":                              "631b646ea085e92f39cbcf8c23a6e03f075b0ea1f00c0b0aeb8e30da3dcfee7c",
			"crypto/tls":                                 "1de2d5bd0f6e7c47239655e4d452544b7aea74fb5bf58e3c11e6b1a596e0874c",
			"crypto/tls/internal/fips140tls":             "83997fde3e86edab4c75542296a31e0448693106c527514d1635a7accb260553",
			"crypto/x509":                                "ca49e90537505f261f33c3175c57049a315ede31e61101d9e30fe68589813e5b",
			"crypto/x509/pkix":                           "b12d2d278ef712f2f35e1117a495e8911cbb276b1924b706bfa61ddd3b506c1c",
			"encoding":                                   "dec092aebe68b90834b423fea28e6dce1766ee1c23d656497bdcaf3eef392690",
			"encoding/asn1":                              "4f1a01c35f712112ae9eb60b27121aff74a8da84407fb1ac872a8b07396e6583",
			"encoding/base32":                            "6ce0b8b02f8b7a8544440446eec41b2dae9b1ba53f0b1b78d59a369d4e7496f5",
			"encoding/base64":                            "4c58ffcd76d0b060a57eaa46562a5bb6319f76f236c498dead2ea1d4dd5dfe4f",
			"encoding/binary":                            "14de28639004b99d71743475e9312d61f65e154372158f91c20e2180a0e17743",
			"encoding/csv":                               "77599c512eb6c429e79872eb6c606ad36a9530e4b62e0cf53a551dffa1290e26",
			"encoding/hex":                               "fd69d1cbeaebf27269a8ff7b7e5d065419ba533ba001e92253638ba100cbb77b",
			"encoding/json":                              "39f05a00cc9c8b0c922ee4ed9d0419c6fe300634c87fa88ea4e6e2f75274240a",
			"encoding/json/internal":                     "27c04913211c0ee8da50dbde7e53ca3394a946c8f53f5312c69bd3fc7177e18c",
			"encoding/json/internal/jsonflags":           "29702b7195faf2244a19eadbbfeea25e0d7de1fd5eafdedc0e7e869da68cf26c",
			"encoding/json/internal/jsonopts":            "5d84dcc77f3f6db328d4dca0660c2eabaeb8b988325c058ac6c4b6f078c7d7d2",
			"encoding/json/internal/jsonwire":            "db2ac82f50627f9645e18acbd5f9663749a26834b2aa949dd72cc94b95fca461",
			"encoding/json/jsontext":                     "867a7db0b1be53f17d6207811c8987c5eafe71f2c59215137315be93fc6c303f",
			"encoding/json/v2":                           "d16bbc6e05bbec377d9b92a75996b8f8e896f2c6861b0079e27fffbf47437902",
			"encoding/pem":                               "faa6fc8ac1de20273b943471427634196476b6d0c6d5b0a1868f72ff4143b64a",
			"encoding/xml":                               "9d402f13caef94067488d58de07ddd1f100f9f44a3d956f860f3ff1131ff8cc9",
			"errors":                                     "4a01f1b0101e800daa6319da35a50cd700525c72287910833e55196095d865f1",
			"flag":                                       "ddf2717c8aedc9c5f15c884b2b563b73cced910b4dc4c8b6b0b140e734d32946",
			"fmt":                                        "abb749d78d0c832de77da40ab3ddc37fc2a5e8e86f29e82370c3078ab6992399",
			"go/ast":                                     "83f014e5ff6d8525ee3d24e4014fac466b9f59a23e3c698545871f02c5bd82c3",
			"go/build/constraint":                        "7c948701c85b759972db8c51549cf5813f09774ca72ff7223615a652f5a35e07",
			"go/parser":                                  "68d96feb07989c4f783ff5f7e18951de958085960d08c766facb7c785af46064",
			"go/scanner":                                 "d0a4a7e90b9dc7293d00319b68b97e4baab72c65faf0f58153cdc37fa92b7545",
			"go/token":                                   "cc80ddf6902dec5799c309f8738a50294c8815463f522390fe083ce4b41d4178",
			"hash":                                       "5407bef958b334dae4b35cb0c6d0d6d4a651b263a51d6d2930f98f94ee71322f",
			"hash/adler32":                               "c982cdd68a23163eff3715d14630b174bf918b7ebdb5c19004106659e050c14b",
			"hash/crc32":                                 "5b86533ffd3403e07ad7bbe26bf609d60be12b39dfc4b4485cbb29e8064a0ab4",
			"hash/crc64":                                 "1c6333929205a1cb0a0c173ee5318752588765d4d6b7cbf7ce3c0c6bc2d56671",
			"hash/fnv":                                   "83fd66bc835b36a14a588612b64f12c902bfc57b225792d10578032c3f9994bf",
			"html":                                       "f3f5658602c81c0efa2e6fe24be65205c2063a12482bb32aa3c2eee4c58e1fd2",
			"html/template":                              "bf3e9c0417da43d59ffa324df5dd15ade23f325842b566c52c1f4ec6042ae600",
			"internal/abi":                               "e9de33bc37f59c65168fb3fdd2ad11f4a07b9874d686014270e0c1709a4d9ae9",
			"internal/asan":                              "ba9be330b3b227367fb57d99d98c178b598c090c3fbdcbe4aae717ba5a524fd0",
			"internal/bisect":                            "b1cd7817e4136133524f2edac7628c71d90dc268ebae134cbc60e3d5d73905f0",
			"internal/bytealg":                           "16f1bbb8a94f512de674928731ed4098e5c97cd230af6c071399211173f3c36c",
			"internal/byteorder":                         "5905eb1255dc8794cd6c6c434b5cb07405ec611e028f8cd55993bc35dae0678e",
			"internal/chacha8rand":                       "df5a88705927727fcc77ad2920cf655495ba83c3397629582074218d48ad5daa",
			"internal/coverage/rtcov":                    "a1864369278a3c4d4c2a9586b69b3225382acdf05f5495e6146583d5a486192f",
			"internal/cpu":                               "d1df4187259984b9db31fa3d5c7c58ea13dbe9615404f66a2d73b5cbde9b54eb",
			"internal/filepathlite":                      "b76d8b8acd599875e09d8a57fc1c429f4b56b9585b6fe078a7f30f7a42c7fa4f",
			"internal/fmtsort":                           "97e2ca3e3fb4622e3bece0a59da38c563e4ff77a807fe125c0ea423101f9b452",
			"internal/fuzz":                              "fa113ba9ec464954187f8ed44bdd77275b834e4669bf58fdebf54336fc038c5f",
			"internal/goarch":                            "9f6089cd61dd3b65a8abc4cfebfa21e6929201c23d3ebbe2bc78793555ffb906",
			"internal/godebug":                           "3efce170324165516b0cd491f85e4cb6ef441d49d1bb0da14d8122a8e1f9c3c0",
			"internal/godebugs":                          "a71b4db402dc174fcd74de45faeffdaa89040be3ac1119c22766266d8789f58f",
			"internal/goexperiment":                      "3a74b2c14f75bec446abce4c6ce212139f4986a686f8c11d28f80de727a5b776",
			"internal/goos":                              "293fb59a7f3dd6a01b725be3b743407e008ab0627ee8195127724e841463f955",
			"internal/msan":                              "2bf7d73a5f6d8a250edb7e196006bdf5bf00bda641474d2a32cfebddc6dc2f3c",
			"internal/nettrace":                          "3edb07b2958034898e228900b3edd2c5fd4cedcaecca7c8d98f421ecb5423bdc",
			"internal/oserror":                           "fb65f6fcbaa4959503b6ecc468cc0a0ddd327ac69ee27e311a07a76bcc581d23",
			"internal/poll":                              "14c9af0fab22ad84959838e2f3090c5d46e234dfc646e72c1e9fb9679e171c70",
			"internal/profilerecord":                     "05ee315827c9531cc16085c8120442387debc6b3f81c2e3c42d9bf13116616c1",
			"internal/race":                              "dc698ab07a4ccd3317535ea3f6ae2c43ddf410e96269bb01951c2898feb73809",
			"internal/reflectlite":                       "83953fbbecbe86dd53a75147da0b5f70407ab1287cae3a50c9d84465c29f2beb",
			"internal/runtime/atomic":                    "7f55d46ad75ff2d3e21d9a1578aad24bb23885085671190a79cd58028442249e",
			"internal/runtime/cgroup":                    "25864c90f64abca88949a71ff93d7842438c965dd0f8cb115dcf38bd4089bf27",
			"internal/runtime/exithook":                  "5006957a530d5b72d1f70ca11258262d8eb46540d21aeafbc5590bfdea43b18b",
			"internal/runtime/gc":                        "c92cef25996b21ed07586c32f8a1ecc415472c2f1299c1abdb560a05740d5e28",
			"internal/runtime/gc/scan":                   "73f3a7818b86efda6a63a301430a2be61b7aab13181e81ef55777b30d86fc5a6",
			"internal/runtime/maps":                      "ecfa24a42cf3f3a4e606dcbfa43a15201e03d7eb8792462d6ca970473000ba82",
			"internal/runtime/math":                      "a801a1ba14c74ce276dbf92a2a8657c970b588dba1161820d2aae77fe26294f3",
			"internal/runtime/pprof/label":               "9c7af14c47b16bf9873f3e71818889e61698d3aed8cd9855343ff0d493e24c95",
			"internal/runtime/sys":                       "51556f35cae924ce5a6dd979438eea5537841166356b86cffa7c4787e1e9ba5b",
			"internal/runtime/syscall/linux":             "34c8666c5ca0cd75d0d621a6817daaef5b2e3d1b51771b5e5cdc8f0cf8cd6e19",
			"internal/saferio":                           "4f8d3fe93e8f2102dfda74fd3a36dbaa10c0c58a14ae8779829a3295431c6a96",
			"internal/singleflight":                      "9bf2114d0a42b2d74b3ceaec9655f86fa550b25d5a7be166db4d4a5885413a91",
			"internal/strconv":                           "9aca65c4838fd1ff2ebc56b7d5b5933c9262513d214b79b748a7456abc89e948",
			"internal/stringslite":                       "21b2fb46d16f1e90fd3ffd491eb1bf1eafd6e6300d867e5b4bf852604834a111",
			"internal/sync":                              "1fdd10daff7e5d2e9b893685e9268708bdd1132c9e7ddfd52dd9e4a84508000a",
			"internal/synctest":                          "5e76b00397c1995db9c4ed691d1b5fe97c7ef6b91c9fd07aa268d53ad8ee0436",
			"internal/syscall/execenv":                   "ec8e82c0bd0b8a977b983284c644125b10a56c83348fcb292845d3318f9d966f",
			"internal/syscall/unix":                      "fa72b7ebd4a781a30471533fae3b678965546cd87fe12be0c96576ed87dd9987",
			"internal/sysinfo":                           "525ca4563c28a8a3836a529dc690e62f416e61b41832591db096fc17ad04b055",
			"internal/testlog":                           "20637a05131bec19e0a51896362120913213519a7605bf66ef6e7aee7e549d8c",
			"internal/trace/tracev2":                     "687c514b265906b421f76d0364f2a51cec787f175f75fe7dbc12bc61d863cfe2",
			"internal/unsafeheader":                      "2462dcfd4b95b12ff0ddedf99eaf612deb2e5b57506d73c90974feef77fbdf67",
			"io":                                         "68bac4216185e39215459b641cd09260f6ee0a03f2d73d1a2c0e7389a31456a5",
			"io/fs":                                      "26fffb13729869f92eb806a2b296b33999bd077a5b9d4fb61d2aa872e4e0ba53",
			"iter":                                       "866724b23bd1440bb72f9eaf4e0e274dcc3301d563c423c2a40ba22075e399e8",
			"log":                                        "2071c7019c5b79533a7e188cdca80e9cfc3d3f82ac45559fcfb3cc299841fb42",
			"log/internal":                               "981ca5d12bf9788b63809ca9c019a6a710276536e1add4a03ea02098781be605",
			"maps":                                       "75fc4028db4ea56966684866694fbe2112090f0acee353cd7d2b05414a2ede69",
			"math":                                       "cb971b22a15d1b0d0c14bec63020cc07495878e5d326edc6291ef91ebda1730d",
			"math/big":                                   "b7a7573798cd7713a70e985227a3d1725db592b3cdab7132dd96c8f842b07a2b",
			"math/bits":                                  "40bd923081f15c3ed371b1835e0933b810cd8d475a474dfadef0f31791a6541c",
			"math/rand":                                  "0cb4f4c1c03da268cfe0eaadc851f0843b6db7834bb29f7cbc31e8774e58c74d",
			"math/rand/v2":                               "37c010a68f594ec8a9d750188ca54177c1331559946ebfb53fd183a441faf4ba",
			"mime":                                       "5c4e1c83ec655251e0c3e44de3fcdad36f198cc31283c3cf34d95734a51d464a",
			"mime/multipart":                             "9d1f9d1ed01930b9f62cc6e5ae4ed7a264675c790d8841353d3b2d71aa369771",
			"mime/quotedprintable":                       "4fe389a6170e8615c16d8b2110707b43834a1c6203e918b2724b7ff18d8ae918",
			"net":                                        "bcaf89df16addb9bccb029d4c1f26a0f10c2f8232df4abc0231b2db303209e51",
			"net/http":                                   "c787fc22e1a4f9d643df3d7f921e4625ed0396c4802871251db7db8e69594d2a",
			"net/http/httptrace":                         "64819dbddfa5019447995f4cc0630cc9a3fe90d01dcb6038fad3bc55b248d8f4",
			"net/http/internal":                          "49e0b4eaa01c185f73588f58dc5d84c57c1699626cf38d9fcf0bb138b7067ef3",
			"net/http/internal/ascii":                    "6e786606272d0993dbcc309a9897719de1c1e30305cbec15634a34b50ae14c8c",
			"net/http/internal/http2":                    "cbf43af8bf45a50a4312f0fb64e80ddb2c52fea47bf6c529d10c0c62eb0958fc",
			"net/http/internal/httpcommon":               "e1c15a563e12137f4890cdbfd11e3f38dbc6ed0b217327ce658c0a3bc25725e2",
			"net/http/internal/httpsfv":                  "d288228841b074b0e2618f7a77d7d369d57844a790ff5b5f24ad082a1479fee6",
			"net/netip":                                  "4210304f5757058d5a55cb99dec569f7e337f73a038d64603bfb17927ba149df",
			"net/textproto":                              "96429d95faf0ff92ce31f73f0fcfdf5baaf326ffda9a276a0107149705ea8621",
			"net/url":                                    "5c9260c9351c45e0a9a53a106ecaafe1ad24af14b14d36a53865b130234dc3f9",
			"os":                                         "0ec270a7b135053977b4d06021f24c3839d6a71a1a800716a2e4f9a129ba97f7",
			"os/exec":                                    "14f5600a9a3c16c57a07db8acfcb328a89f0ab234d79ab35a8d43bab8f4b7118",
			"os/signal":                                  "ea452cdb87327da289c9429c0ae0b821039c23c600d1fcb6cf8aa2fe3f6fd8cf",
			"path":                                       "96a7ba98bffe4f9eee28b78041593d2bbbace5285f1a27bfb29f4340dd839133",
			"path/filepath":                              "7407945484ec2ab1170561d7faf860fe1341c5e8e6112c99cb2dc9897b342884",
			"plugin":                                     "20d4a1dcab3abdcca97e7107c9e5497ca684c6cea9c437cfaf5f51fb29a9dd8e",
			"reflect":                                    "c54e484c19b4212650743ea16dd135b8b3a2d345a0073ad17248e17c179d0350",
			"regexp":                                     "b33455e689ad00dd500d5f583136a3305d6c3ae226c5362bb18d5d4f001fbb19",
			"regexp/syntax":                              "5c3d1ac50170b5e321e099c6da1e9fbb8c2d2846e8f85485e19570045c2c0ec3",
			"runtime":                                    "5ab2b8181b8acda54a0414b9d5909ed19b80e0981411bb22f2f585214924c8a4",
			"runtime/cgo":                                "c2f6226cd1f19b7e816812e0613e8886539aad42cec61465e78d31eb5160e2a5",
			"runtime/debug":                              "6d998511378a4311849176e0568aeb82a33247c6e867b2d9e7f7bde5461cf082",
			"runtime/pprof":                              "f31c0e00bd79fa9fe55cd2d7bc7131e643e6f4010fc2832c41480aa0e2b2fbdc",
			"runtime/race":                               "57e001507a69dae45c7dbe28ad9c4fc56b962c28b890995dd8196f2680bc8d89",
			"runtime/race/internal/amd64v1":              "a1a6d164d4917e28ede11ddae2d083b90a3f9182463e4bd52651f44bd8077226",
			"runtime/trace":                              "cba7ea21422ef5ab44862b5e5357e0687033825fc578ebb2434f15677f72e9bf",
			"slices":                                     "0e33fea124736fc93fcad23cd4ae888726d7a94bd4862ee4ea4dc3df4a4e5019",
			"sort":                                       "7089f000ca28205b9c5e6b6a5ccbf2759ee68a84eac0226e2bb63a37b633770e",
			"strconv":                                    "26eeab21bd4de61fd56c5fbabac70b9959a93d3d8fdf13c8c22b5f23c7ffa3f9",
			"strings":                                    "e1af4a4a7186d9dabfbf9249a8b31668581a4b0e35f5b24c513c0e05dfe82fa3",
			"sync":                                       "8883745b873274852d8c2e94e8f70252f7a30af529913dd2243a38930e1f946d",
			"sync/atomic":                                "e7841bc90451d1b9fa58f5d1abfd572a87bc3afeb91f123df7caa30c8d519667",
			"syscall":                                    "46a56f2b142264eed3a617bd9264f8599b1cfc1e7d0741ec8bdfa76233d29d37",
			"testing":                                    "26c2429747ac0d571e375d23ba223278bd0958986e4fe00a0d26fa8b9da1ad4d",
			"testing/internal/testdeps":                  "a02b564be46615d4bf22618c3990afd3f7ac6be6cc92e038eb734f17499ab5d1",
			"text/scanner":                               "d3f99bab57d66079d61384a328991c97826b6e4e35c16b9507c674f3d5e61510",
			"text/tabwriter":                             "d285eff37fe9df71c1e9d909e0cf5498f5a7a6ef6999a4f887da7b274dc3e0f9",
			"text/template":                              "9bc72279ce9f48b1d0f09c6b266ae1c14efd7df0daee07f548852b7e6f926feb",
			"text/template/parse":                        "982fcb29e1365db8f04e33cade90ac9a57bbd6769e2306b636e9d0c11b1be92e",
			"time":                                       "22d2681e16c146ef33543cae2fb665a5a8ec0d12fea6364e3f8ab877d74aa131",
			"unicode":                                    "b1b772c7baa0f9da0c000ce465401e6f32e8ddf29f57b3813836c1659d422354",
			"unicode/utf16":                              "3d2f8207442cfba4503e001b5b628e3753c3f35b6c73876be86f887b21491f80",
			"unicode/utf8":                               "ac26172bb28dc0c69eb8756d5e0a97be40e97a087e729af38cbea387c82e4b91",
			"unique":                                     "ae78b7c154907fb974095437bed9de53b925b6479feef3921af09aa5b8b65cb0",
			"unsafe":                                     "36f9a162c58b2133d452f79888b98d08d7153b013d002a66636560188f35405e",
			"vendor/golang.org/x/crypto/chacha20":        "9e0b97acc0529805afc5b65b7ef13b7ab0fe58d1a9d8911584d162d4435f36c8",
			"vendor/golang.org/x/crypto/chacha20poly1305":  "31ccc70c9d432b4d612d85424a95b6f98d8c68ab21f5e3593f8bd6ae0b762372",
			"vendor/golang.org/x/crypto/cryptobyte":        "eaffc169bd3cfdb54d5f4beefe15ebc4123724487affe2b3930495b1935ee412",
			"vendor/golang.org/x/crypto/cryptobyte/asn1":   "cf13e2dfd027ec44f973c501ec238edda6662b0efdad5aa0bcbb8cc6425e77f4",
			"vendor/golang.org/x/crypto/internal/alias":    "a654344a35b38da2d4cf206a8cde6adccccdad6b4342c1f2d812162d2854988f",
			"vendor/golang.org/x/crypto/internal/poly1305": "d7bde5a36139d83a920d8c0fc2711af620c051433a56d94a7824506b6a193859",
			"vendor/golang.org/x/net/dns/dnsmessage":       "4c8d1275b5a3af5cbd99c3243f8ec8efefc63d54d6b373b3a32ac90a642ffe83",
			"vendor/golang.org/x/net/http/httpguts":        "75ac4730a846e1b62aa596bfeb967685cc85e0427f0b5ad28f0c762da39ce1c6",
			"vendor/golang.org/x/net/http/httpproxy":       "ce58539caf1cfa693b4944722406ea0d0aceff34fbcef704823b35fa5e517173",
			"vendor/golang.org/x/net/http2/hpack":          "474ae4f6d051dcb3e07c06b65ad103d690f36730b02dc1e84bc7f1830354f99f",
			"vendor/golang.org/x/net/idna":                 "8c994664bb4834cb553e1fba844bdae7c32048300b7d6026c8c8ed4142d2abeb",
			"vendor/golang.org/x/sys/cpu":                  "7e228e4e8b046d0d9ee074719ab3ce29afe0c78c028eaa2ce20b8cd8ff4476d1",
			"vendor/golang.org/x/text/secure/bidirule":     "c53706f0dc7f8807df6f45079135df7a109b7b702b92e63adbcb31e501b1751a",
			"vendor/golang.org/x/text/transform":           "eeac178876252e8025492cad77c2dea2c7ed93569613bfef4a422ae92cf81381",
			"vendor/golang.org/x/text/unicode/bidi":        "80f14e21240ff9a25e64ffd4551d0cacfac552c8d4fab66b6d34447b63a4b8e7",
			"vendor/golang.org/x/text/unicode/norm":        "f03c2d3712972f532925f59a65a3107ffb9267779cafa9faa71553c81d6c7efe",
			"weak":                                         "8a95bd5b0fb475e14c0aaa99d5ce4504597f54fdab330f674435f467fe74a5e8",
		},
	},
	// The race selection (-race) over each toolchain's chain: the race
	// seams — internal/race selects race.go for norace.go (sync's
	// delegate, the instrumentation behind the race.Enabled guards),
	// sync/atomic selects race.s for asm.s (the atomics routed through
	// the runtime's instrumented forms), the runtime and its sys
	// delegate select their race files, and the detector's runtime
	// (runtime/race, linked without an import) its race-tagged files
	// — judged inert for every admission; a row per toolchain over
	// its own chain, since the runtime's race file carries each
	// toolchain's own bytes.
	{
		Label: "go1.27.1-dst.13 race",
		Base:  "go1.27.1-dst.13",
		Packages: map[string]string{
			"internal/race":        "e80429a1ec958b17e616e45f07b6b6f6cd205a925896d2268f95cb19da585dc5",
			"internal/runtime/sys": "508268ec7dd881dad867d5d8ccfe777ee12c3b68de5e5c19051311eea63251bc",
			"runtime":              "7144c5186255ebe0f322d0d59181004bcf23732600d6cec510995ba3d51974d0",
			"runtime/race":         "286c7e1ff0150cf2df8713e402d61c6a93c0f5f938bc3f220a6e35026782043c",
			"sync/atomic":          "6f499cf4f7d682fbdf6ac4ded188a15d21c48854a80a04aaf5c08939f2c717e0",
		},
	},
	// The plan9/amd64 platform over each toolchain's chain (listed from
	// this host: the split files are in the one GOROOT; the audited
	// packages' were read whole by the walks, the deeper packages ride
	// the toolchain judgment): the packages whose selection differs
	// from linux/amd64's — the runtime's, syscall's, poll's, os's,
	// net's and time's platform files, plugin and the cgo-dependent
	// x509/mime/sysinfo/cpu delegates, the bytealg and filepathlite
	// assembly splits.
	{
		Label: "go1.27.1-dst.13 plan9/amd64",
		Base:  "go1.27.1-dst.13",
		Packages: map[string]string{
			"crypto/internal/sysrand":     "499920ccaa5f962a8f0d10557ba32d5e7604c1f831c6af4d1d8a2e83e0796657",
			"crypto/x509":                 "e373324ba6d8be424d8d3bdafe3480eccc1b5bce1249f7f5554b9bbbeffab06f",
			"internal/bytealg":            "9edabccd7d8972a52f4cdeaf43faf6fb035c837214c2d1de91ccead42a619546",
			"internal/filepathlite":       "07fbc7b432b0c2c924d3cff03eb8265e93fb286491aea80201501795f8a40872",
			"internal/fuzz":               "a3dc4cef6a19709eaa811f5801b8933983fb16be979b65c7f694ed58cdcd9003",
			"internal/goos":               "2c261770f7872d52fad29d60c41a1c77ded1efeac849c3c6bc3a4b99afb2de1a",
			"internal/poll":               "53c15da3d437d242781cb300fdeda446d4d8c41ff86a83f048950b9e664bcf57",
			"internal/sysinfo":            "4b67cd60d2c15f926b34def981df7cadca0908305d1096932a055f6cb3f1965c",
			"mime":                        "57ab58c0a78c521ac4c0d94bf3b983a8eee260c1b98cc933976fea1f553a6cfd",
			"net":                         "cb030b0f41e93b0739f036074cf0c7a32b7a52bd530fe2b7bde3a96bacc96b93",
			"os":                          "fdc286ff2c125bf3921006940c20977a93503ddc977774eafc16b879d4f4e2c8",
			"os/exec":                     "3bf7bf76ec6f6556ef250a290f8837bccb94a54d8a3789957aba5269bd14d202",
			"os/signal":                   "07a2d3c2b0456b150969592f7835b63b724c70172e2bfe156f71564844010703",
			"path/filepath":               "2bca3fd096d61b21b4a7589bff53bfac85c1a9a793121f57be981583eb2c13cc",
			"plugin":                      "a7621873f1d13b052288814d5e0c517f88d748c857168f080aa5e51e8c29a921",
			"runtime":                     "72ded8e8abeea70cc35baaf8dc404de1d558503239bdf2be293585bbf9c8ee21",
			"runtime/pprof":               "20a600b3e95c92a5300a77a5d47c3875f48d70c759e5818f774ec6ab8854fb1e",
			"runtime/race":                "4a07f81aac3ba889c683d6eac16dd0296cd69ab3a519fd9d40c9e7b3ee524284",
			"syscall":                     "958877a17f8e19d4affb1d870acfe927a469d39bca2ca28358c71e828fc242b2",
			"time":                        "b581538d74c82f785183f10729e856cfbc5eacefa0b8ca5e2377f4da0674edc3",
			"vendor/golang.org/x/sys/cpu": "345ea2e752f7b4f79a427a074ef04bb32a9a19fea34766d502e8346f7c6370b8",
		},
	},
	// cgo off over each toolchain's chain (listed from this host on the
	// same terms): net selects its cgo stub for the cgo resolver files,
	// plugin its stub, and the cgo bridge (runtime/cgo, still a listed
	// dependency) its stub set.
	{
		Label: "go1.27.1-dst.13 cgo0",
		Base:  "go1.27.1-dst.13",
		Packages: map[string]string{
			"net":    "c80c61d75dd2dcd5aabe9241df9e929fea7d826edc702ef6157b0d47d50900bb",
			"plugin": "a7621873f1d13b052288814d5e0c517f88d748c857168f080aa5e51e8c29a921",
		},
	},
	// Stock go1.27.1 (the dl tool's tree), over the dst.13 chain: the
	// ten keys the godst hooks touch, stock's bytes; its race, plan9 and
	// cgo-off rows over its own chain.
	{
		Label: "go1.27.1",
		Base:  "go1.27.1-dst.13",
		Packages: map[string]string{
			"crypto/internal/sysrand": "a9fbcbae3c3bd34fb1c2dbcc31024ba11ded85aba54ae4ac1e7df1b4637d90b1",
			"internal/runtime/maps":   "16209ec91d056a47c7e6f93de1aab2ae03f068de0d2ca80521fd1bcc26e36a94",
			"internal/sync":           "23a76fa933f99d093e54bccab4152a34cf23e4396d24e53bdfbf2ba254f8a18a",
			"net":                     "8235633266f1518b4b72986af0c3938c02c084c40df55176263616760233c84d",
			"os":                      "57676d0cb0d27d5fa8bc327a69595e1ccdee28322cc5c67fe0578a24eddca88b",
			"os/signal":               "c2ef67378706283c9a5a31884d973a766d24c7419cde943533a85837e4c1f28b",
			"runtime":                 "f2ac830cb077c858296f5f87f5bb6ffae816b76c22434b422e3dde0b2d12233e",
			"sync":                    "6dac345cc89accb770ead63ee5118f36720532b11b622eeb6056317b1e52baa4",
			"syscall":                 "c7cecb7fb84bd25c3b127607940a22ff774bc30cc2160216c9f6af9704780f77",
			"testing":                 "b79f85afecd764d620bb147419f8968c1b17f6013e69f0712d5c3caecc35b87a",
			"time":                    "a562f66a34d0b3bd9b775f806db34e9b2fe9f675ba94106db3d437b9af391810",
		},
	},
	{
		Label: "go1.27.1 race",
		Base:  "go1.27.1",
		Packages: map[string]string{
			"internal/race":        "e80429a1ec958b17e616e45f07b6b6f6cd205a925896d2268f95cb19da585dc5",
			"internal/runtime/sys": "508268ec7dd881dad867d5d8ccfe777ee12c3b68de5e5c19051311eea63251bc",
			"runtime":              "03f63c5da14e3825c5adcffb7911a40837e1689cd004409cb7f7e0b0619d8863",
			"runtime/race":         "286c7e1ff0150cf2df8713e402d61c6a93c0f5f938bc3f220a6e35026782043c",
			"sync/atomic":          "6f499cf4f7d682fbdf6ac4ded188a15d21c48854a80a04aaf5c08939f2c717e0",
		},
	},
	{
		Label: "go1.27.1 plan9/amd64",
		Base:  "go1.27.1",
		Packages: map[string]string{
			"crypto/internal/sysrand":     "e9a964825483a4de332fe115d57b8669ed7acbcd1cf6099f94ea6f96343aa84d",
			"crypto/x509":                 "e373324ba6d8be424d8d3bdafe3480eccc1b5bce1249f7f5554b9bbbeffab06f",
			"internal/bytealg":            "9edabccd7d8972a52f4cdeaf43faf6fb035c837214c2d1de91ccead42a619546",
			"internal/filepathlite":       "07fbc7b432b0c2c924d3cff03eb8265e93fb286491aea80201501795f8a40872",
			"internal/fuzz":               "a3dc4cef6a19709eaa811f5801b8933983fb16be979b65c7f694ed58cdcd9003",
			"internal/goos":               "2c261770f7872d52fad29d60c41a1c77ded1efeac849c3c6bc3a4b99afb2de1a",
			"internal/poll":               "53c15da3d437d242781cb300fdeda446d4d8c41ff86a83f048950b9e664bcf57",
			"internal/sysinfo":            "4b67cd60d2c15f926b34def981df7cadca0908305d1096932a055f6cb3f1965c",
			"mime":                        "57ab58c0a78c521ac4c0d94bf3b983a8eee260c1b98cc933976fea1f553a6cfd",
			"net":                         "eb3bbf18fcf139b9116d3cd6847f5ba52178349347d4e1dd75522906875f622d",
			"os":                          "260b9ccfad18429175eb866fb5701b6cda116461bd214c0117eb648fe176cf9d",
			"os/exec":                     "3bf7bf76ec6f6556ef250a290f8837bccb94a54d8a3789957aba5269bd14d202",
			"os/signal":                   "2e131909d0102bc295bce4c8e579ac5142fbd38f9c3cc49563758118068e90c4",
			"path/filepath":               "2bca3fd096d61b21b4a7589bff53bfac85c1a9a793121f57be981583eb2c13cc",
			"plugin":                      "a7621873f1d13b052288814d5e0c517f88d748c857168f080aa5e51e8c29a921",
			"runtime":                     "9a35fe7f5ee7264805e3e3d153f3dce437aa0779798f7f7e82ad1f41d7ee825b",
			"runtime/pprof":               "20a600b3e95c92a5300a77a5d47c3875f48d70c759e5818f774ec6ab8854fb1e",
			"runtime/race":                "4a07f81aac3ba889c683d6eac16dd0296cd69ab3a519fd9d40c9e7b3ee524284",
			"syscall":                     "b81f6c90213b3e8485343abc31f3ecf884084d12f3caf95dd7601b8e8b2e1c75",
			"time":                        "088f86c38caf2b2a52b1cca6e74561bf3df5e39662e73c29bb1e9fdda64213b1",
			"vendor/golang.org/x/sys/cpu": "345ea2e752f7b4f79a427a074ef04bb32a9a19fea34766d502e8346f7c6370b8",
		},
	},
	{
		Label: "go1.27.1 cgo0",
		Base:  "go1.27.1",
		Packages: map[string]string{
			"net":    "24ff91ed9c0e683918309399ba24d80c9edf432de3240537d4daaf3763255c1b",
			"plugin": "a7621873f1d13b052288814d5e0c517f88d748c857168f080aa5e51e8c29a921",
		},
	},
	// Disabling DWARF 5 selects only the alternate goexperiment constants;
	// it introduces no effectful standard-library body. Code-generation
	// differences remain guarded by the toolchain and build configuration.
	{
		Label: "go1.27.1-X:nodwarf5",
		Base:  "go1.27.1",
		Packages: map[string]string{
			"internal/goexperiment": "6970d45d798281d7e388da92e9c7160901094abc95ae3a09de1bd8de69b1324e",
		},
	},
	{
		Label: "go1.27.1-X:nodwarf5 race",
		Base:  "go1.27.1-X:nodwarf5",
		Packages: map[string]string{
			"internal/race":        "e80429a1ec958b17e616e45f07b6b6f6cd205a925896d2268f95cb19da585dc5",
			"internal/runtime/sys": "508268ec7dd881dad867d5d8ccfe777ee12c3b68de5e5c19051311eea63251bc",
			"runtime":              "03f63c5da14e3825c5adcffb7911a40837e1689cd004409cb7f7e0b0619d8863",
			"runtime/race":         "286c7e1ff0150cf2df8713e402d61c6a93c0f5f938bc3f220a6e35026782043c",
			"sync/atomic":          "6f499cf4f7d682fbdf6ac4ded188a15d21c48854a80a04aaf5c08939f2c717e0",
		},
	},
	{
		Label: "go1.27.1-X:nodwarf5 plan9/amd64",
		Base:  "go1.27.1-X:nodwarf5",
		Packages: map[string]string{
			"crypto/internal/sysrand":     "e9a964825483a4de332fe115d57b8669ed7acbcd1cf6099f94ea6f96343aa84d",
			"crypto/x509":                 "e373324ba6d8be424d8d3bdafe3480eccc1b5bce1249f7f5554b9bbbeffab06f",
			"internal/bytealg":            "9edabccd7d8972a52f4cdeaf43faf6fb035c837214c2d1de91ccead42a619546",
			"internal/filepathlite":       "07fbc7b432b0c2c924d3cff03eb8265e93fb286491aea80201501795f8a40872",
			"internal/goos":               "2c261770f7872d52fad29d60c41a1c77ded1efeac849c3c6bc3a4b99afb2de1a",
			"internal/poll":               "53c15da3d437d242781cb300fdeda446d4d8c41ff86a83f048950b9e664bcf57",
			"internal/sysinfo":            "4b67cd60d2c15f926b34def981df7cadca0908305d1096932a055f6cb3f1965c",
			"mime":                        "57ab58c0a78c521ac4c0d94bf3b983a8eee260c1b98cc933976fea1f553a6cfd",
			"net":                         "eb3bbf18fcf139b9116d3cd6847f5ba52178349347d4e1dd75522906875f622d",
			"os":                          "260b9ccfad18429175eb866fb5701b6cda116461bd214c0117eb648fe176cf9d",
			"path/filepath":               "2bca3fd096d61b21b4a7589bff53bfac85c1a9a793121f57be981583eb2c13cc",
			"plugin":                      "a7621873f1d13b052288814d5e0c517f88d748c857168f080aa5e51e8c29a921",
			"runtime":                     "9a35fe7f5ee7264805e3e3d153f3dce437aa0779798f7f7e82ad1f41d7ee825b",
			"runtime/race":                "4a07f81aac3ba889c683d6eac16dd0296cd69ab3a519fd9d40c9e7b3ee524284",
			"syscall":                     "b81f6c90213b3e8485343abc31f3ecf884084d12f3caf95dd7601b8e8b2e1c75",
			"time":                        "088f86c38caf2b2a52b1cca6e74561bf3df5e39662e73c29bb1e9fdda64213b1",
			"vendor/golang.org/x/sys/cpu": "345ea2e752f7b4f79a427a074ef04bb32a9a19fea34766d502e8346f7c6370b8",
		},
	},
	{
		Label: "go1.27.1-X:nodwarf5 cgo0",
		Base:  "go1.27.1-X:nodwarf5",
		Packages: map[string]string{
			"net":    "24ff91ed9c0e683918309399ba24d80c9edf432de3240537d4daaf3763255c1b",
			"plugin": "a7621873f1d13b052288814d5e0c517f88d748c857168f080aa5e51e8c29a921",
		},
	},
	// Stock go1.27.0 (the dl tool's tree), over go1.27.1's chain: the
	// three keys the point release moved — encoding/json, its v2
	// engine, net/http — exactly the walk's three audited-surface
	// entries; its race, plan9 and cgo-off rows over its own chain.
	{
		Label: "go1.27.0",
		Base:  "go1.27.1",
		Packages: map[string]string{
			"encoding/json":    "3f63a3171e77a88ac6add4ad53d0322a389332ee0a6a164bf0fc781e7dc7ef45",
			"encoding/json/v2": "8a5b6fd60b75e360b663e57e0ce9ea4d5144f91aab89cf71f81273efc5c23911",
			"net/http":         "1ff6fe177965e0d683ce814e2d48c96fb12b179fec92b62fc42d97dd655ef4ef",
		},
	},
	{
		Label: "go1.27.0 race",
		Base:  "go1.27.0",
		Packages: map[string]string{
			"internal/race":        "e80429a1ec958b17e616e45f07b6b6f6cd205a925896d2268f95cb19da585dc5",
			"internal/runtime/sys": "508268ec7dd881dad867d5d8ccfe777ee12c3b68de5e5c19051311eea63251bc",
			"runtime":              "03f63c5da14e3825c5adcffb7911a40837e1689cd004409cb7f7e0b0619d8863",
			"runtime/race":         "286c7e1ff0150cf2df8713e402d61c6a93c0f5f938bc3f220a6e35026782043c",
			"sync/atomic":          "6f499cf4f7d682fbdf6ac4ded188a15d21c48854a80a04aaf5c08939f2c717e0",
		},
	},
	{
		Label: "go1.27.0 plan9/amd64",
		Base:  "go1.27.0",
		Packages: map[string]string{
			"crypto/internal/sysrand":     "e9a964825483a4de332fe115d57b8669ed7acbcd1cf6099f94ea6f96343aa84d",
			"crypto/x509":                 "e373324ba6d8be424d8d3bdafe3480eccc1b5bce1249f7f5554b9bbbeffab06f",
			"internal/bytealg":            "9edabccd7d8972a52f4cdeaf43faf6fb035c837214c2d1de91ccead42a619546",
			"internal/filepathlite":       "07fbc7b432b0c2c924d3cff03eb8265e93fb286491aea80201501795f8a40872",
			"internal/fuzz":               "a3dc4cef6a19709eaa811f5801b8933983fb16be979b65c7f694ed58cdcd9003",
			"internal/goos":               "2c261770f7872d52fad29d60c41a1c77ded1efeac849c3c6bc3a4b99afb2de1a",
			"internal/poll":               "53c15da3d437d242781cb300fdeda446d4d8c41ff86a83f048950b9e664bcf57",
			"internal/sysinfo":            "4b67cd60d2c15f926b34def981df7cadca0908305d1096932a055f6cb3f1965c",
			"mime":                        "57ab58c0a78c521ac4c0d94bf3b983a8eee260c1b98cc933976fea1f553a6cfd",
			"net":                         "eb3bbf18fcf139b9116d3cd6847f5ba52178349347d4e1dd75522906875f622d",
			"os":                          "260b9ccfad18429175eb866fb5701b6cda116461bd214c0117eb648fe176cf9d",
			"os/exec":                     "3bf7bf76ec6f6556ef250a290f8837bccb94a54d8a3789957aba5269bd14d202",
			"os/signal":                   "2e131909d0102bc295bce4c8e579ac5142fbd38f9c3cc49563758118068e90c4",
			"path/filepath":               "2bca3fd096d61b21b4a7589bff53bfac85c1a9a793121f57be981583eb2c13cc",
			"plugin":                      "a7621873f1d13b052288814d5e0c517f88d748c857168f080aa5e51e8c29a921",
			"runtime":                     "9a35fe7f5ee7264805e3e3d153f3dce437aa0779798f7f7e82ad1f41d7ee825b",
			"runtime/pprof":               "20a600b3e95c92a5300a77a5d47c3875f48d70c759e5818f774ec6ab8854fb1e",
			"runtime/race":                "4a07f81aac3ba889c683d6eac16dd0296cd69ab3a519fd9d40c9e7b3ee524284",
			"syscall":                     "b81f6c90213b3e8485343abc31f3ecf884084d12f3caf95dd7601b8e8b2e1c75",
			"time":                        "088f86c38caf2b2a52b1cca6e74561bf3df5e39662e73c29bb1e9fdda64213b1",
			"vendor/golang.org/x/sys/cpu": "345ea2e752f7b4f79a427a074ef04bb32a9a19fea34766d502e8346f7c6370b8",
		},
	},
	{
		Label: "go1.27.0 cgo0",
		Base:  "go1.27.0",
		Packages: map[string]string{
			"net":    "24ff91ed9c0e683918309399ba24d80c9edf432de3240537d4daaf3763255c1b",
			"plugin": "a7621873f1d13b052288814d5e0c517f88d748c857168f080aa5e51e8c29a921",
		},
	},
	// Go 1.27.2 keeps the audited value and descriptor operations closed:
	// JSON/flate/template fixes transform supplied values; HTTP/TLS and
	// the new range-limit GODEBUG remain outside the pure admissions.
	// Runtime itab deduplication preserves descriptor identity. The
	// harness keeps failed test-log writes fatal and escapes diagnostic
	// framing only in its JSON mode.
	{
		Label: "go1.27.2",
		Base:  "go1.27.1",
		Packages: map[string]string{
			"compress/flate":                "49ba38547a8744dbec4ad963d2af020ecaf985e5ff024213e39ad2600e08362d",
			"crypto/internal/fips140/mlkem": "ec8a11c2b67ac5be9230ff71a7b66f8ae77f89ec7aa593c082232e21fce99597",
			"crypto/tls":                    "6c7719835ce0f2ccb49ad96c6cd50c53e6858aee827ab6ea7dbf0398efb5eb19",
			"encoding/json":                 "2913283d6caf96104f107f858be872ee9659af95ad6c8f1369c55fb284270ccb",
			"encoding/json/internal":        "60c2411409d978525f9c78bed819455dfc3813e89c7b42e5204957efa74d0131",
			"encoding/json/v2":              "fd15a7415e6520ea4e4e507b9beb72e0e2f8dbf542f0b22c4562092e86409026",
			"html/template":                 "0c3e0a0c737d647d72c7a8f8571131882c17f72a78c0a62568c6bd873a21f5ab",
			"internal/godebugs":             "e37bd6284b69a14411325e2cb52d1f7b8bbb3be24d7e684dc894e32f53185e59",
			"mime/multipart":                "3255c2ab43d62a15ce19cc0494edcd61f4375666c4393304b31c70d63a7810f6",
			"net/http":                      "3083c50b258b99e1b26ef5ceb4379bc4f702a773351c2a748df7fdb6bcfabea7",
			"net/http/internal/http2":       "f3fe08a1e8bb0425f1da0231bd046626d33d781ee00ceb172aec76f51dedba29",
			"net/textproto":                 "3be0df3fdbd14806727a6f55f1100b9edc953cd6c3ed0aaddf0793d2ca48c369",
			"os":                            "9d9276a1bde36da055e18058486ed58da251ef9dd25c6dc9d78dfc09441f6e79",
			"runtime":                       "424e69dcfe315fa231c794e0c97f6ecaea656bc2997770c53d11725e73e824c3",
			"testing":                       "71fabe8486856ffb5c701678da11de9ca9fc6e38f91f38cfb58c4bec241f199f",
		},
	},
	{
		Label: "go1.27.2 race",
		Base:  "go1.27.2",
		Packages: map[string]string{
			"internal/race":        "e80429a1ec958b17e616e45f07b6b6f6cd205a925896d2268f95cb19da585dc5",
			"internal/runtime/sys": "508268ec7dd881dad867d5d8ccfe777ee12c3b68de5e5c19051311eea63251bc",
			"runtime":              "89533012b8e485a40370ce1d736aee6b3f4c9a5169de895e370208cfc8e1f46f",
			"runtime/race":         "286c7e1ff0150cf2df8713e402d61c6a93c0f5f938bc3f220a6e35026782043c",
			"sync/atomic":          "6f499cf4f7d682fbdf6ac4ded188a15d21c48854a80a04aaf5c08939f2c717e0",
		},
	},
	{
		Label: "go1.27.2 plan9/amd64",
		Base:  "go1.27.1 plan9/amd64",
		Packages: map[string]string{
			"compress/flate":                "49ba38547a8744dbec4ad963d2af020ecaf985e5ff024213e39ad2600e08362d",
			"crypto/internal/fips140/mlkem": "ec8a11c2b67ac5be9230ff71a7b66f8ae77f89ec7aa593c082232e21fce99597",
			"crypto/tls":                    "6c7719835ce0f2ccb49ad96c6cd50c53e6858aee827ab6ea7dbf0398efb5eb19",
			"encoding/json":                 "2913283d6caf96104f107f858be872ee9659af95ad6c8f1369c55fb284270ccb",
			"encoding/json/internal":        "60c2411409d978525f9c78bed819455dfc3813e89c7b42e5204957efa74d0131",
			"encoding/json/v2":              "fd15a7415e6520ea4e4e507b9beb72e0e2f8dbf542f0b22c4562092e86409026",
			"html/template":                 "0c3e0a0c737d647d72c7a8f8571131882c17f72a78c0a62568c6bd873a21f5ab",
			"internal/godebugs":             "e37bd6284b69a14411325e2cb52d1f7b8bbb3be24d7e684dc894e32f53185e59",
			"mime/multipart":                "3255c2ab43d62a15ce19cc0494edcd61f4375666c4393304b31c70d63a7810f6",
			"net/http":                      "3083c50b258b99e1b26ef5ceb4379bc4f702a773351c2a748df7fdb6bcfabea7",
			"net/http/internal/http2":       "f3fe08a1e8bb0425f1da0231bd046626d33d781ee00ceb172aec76f51dedba29",
			"net/textproto":                 "3be0df3fdbd14806727a6f55f1100b9edc953cd6c3ed0aaddf0793d2ca48c369",
			"runtime":                       "c957f836c2d3aab2e1be5e44fbc003161beb64777cdce57149ee5f8a5212be77",
			"testing":                       "71fabe8486856ffb5c701678da11de9ca9fc6e38f91f38cfb58c4bec241f199f",
		},
	},
	{
		Label: "go1.27.2 cgo0",
		Base:  "go1.27.2",
		Packages: map[string]string{
			"net":    "24ff91ed9c0e683918309399ba24d80c9edf432de3240537d4daaf3763255c1b",
			"plugin": "a7621873f1d13b052288814d5e0c517f88d748c857168f080aa5e51e8c29a921",
		},
	},
	// The repaired godst harness returns every test-log write failure to
	// the buffered logger, whose flush fails the process. Its free-function
	// printer/stat helpers preserve observation routing; finalizer scratch
	// remains private to each driver. The dst changes below keep entropy,
	// network and syscall effects outside pure admissions; filesystem
	// operations stay host-isolated, time fences exclude ambient locations,
	// and synchronization hooks change scheduling rather than input values.
	{
		Label: "go1.27.2-dst.15",
		Base:  "go1.27.1-dst.13",
		Packages: map[string]string{
			"compress/flate":                "49ba38547a8744dbec4ad963d2af020ecaf985e5ff024213e39ad2600e08362d",
			"crypto/internal/fips140/mlkem": "ec8a11c2b67ac5be9230ff71a7b66f8ae77f89ec7aa593c082232e21fce99597",
			"crypto/tls":                    "6c7719835ce0f2ccb49ad96c6cd50c53e6858aee827ab6ea7dbf0398efb5eb19",
			"encoding/json":                 "2913283d6caf96104f107f858be872ee9659af95ad6c8f1369c55fb284270ccb",
			"encoding/json/internal":        "60c2411409d978525f9c78bed819455dfc3813e89c7b42e5204957efa74d0131",
			"encoding/json/v2":              "fd15a7415e6520ea4e4e507b9beb72e0e2f8dbf542f0b22c4562092e86409026",
			"html/template":                 "0c3e0a0c737d647d72c7a8f8571131882c17f72a78c0a62568c6bd873a21f5ab",
			"internal/godebugs":             "e37bd6284b69a14411325e2cb52d1f7b8bbb3be24d7e684dc894e32f53185e59",
			"mime/multipart":                "3255c2ab43d62a15ce19cc0494edcd61f4375666c4393304b31c70d63a7810f6",
			"net/http":                      "3083c50b258b99e1b26ef5ceb4379bc4f702a773351c2a748df7fdb6bcfabea7",
			"net/http/internal/http2":       "f3fe08a1e8bb0425f1da0231bd046626d33d781ee00ceb172aec76f51dedba29",
			"net/textproto":                 "3be0df3fdbd14806727a6f55f1100b9edc953cd6c3ed0aaddf0793d2ca48c369",
			"os":                            "6fcb35528633479014875dcb58546a1ba912f2672bfc0339af556324c80a951b",
			"runtime":                       "28aa07d108afaa90f748307e04f3dfebef6852a4985a651ba56df7defdd87cc0",
			"testing":                       "628e2d844a514bc924f1a5f3da6cfa1e0a2b92e6c89ae30abcab54bd6ae7526c",
		},
	},
	{
		Label: "go1.27.2-dst.15 race",
		Base:  "go1.27.2-dst.15",
		Packages: map[string]string{
			"internal/race":        "e80429a1ec958b17e616e45f07b6b6f6cd205a925896d2268f95cb19da585dc5",
			"internal/runtime/sys": "508268ec7dd881dad867d5d8ccfe777ee12c3b68de5e5c19051311eea63251bc",
			"runtime":              "401093aec564b86dd5ce75aab8e4082b020f386ff144d263e0e5f621796ca3c1",
			"runtime/race":         "286c7e1ff0150cf2df8713e402d61c6a93c0f5f938bc3f220a6e35026782043c",
			"sync/atomic":          "6f499cf4f7d682fbdf6ac4ded188a15d21c48854a80a04aaf5c08939f2c717e0",
		},
	},
	{
		Label: "go1.27.2-dst.15 plan9/amd64",
		Base:  "go1.27.1-dst.13 plan9/amd64",
		Packages: map[string]string{
			"compress/flate":                "49ba38547a8744dbec4ad963d2af020ecaf985e5ff024213e39ad2600e08362d",
			"crypto/internal/fips140/mlkem": "ec8a11c2b67ac5be9230ff71a7b66f8ae77f89ec7aa593c082232e21fce99597",
			"crypto/tls":                    "6c7719835ce0f2ccb49ad96c6cd50c53e6858aee827ab6ea7dbf0398efb5eb19",
			"encoding/json":                 "2913283d6caf96104f107f858be872ee9659af95ad6c8f1369c55fb284270ccb",
			"encoding/json/internal":        "60c2411409d978525f9c78bed819455dfc3813e89c7b42e5204957efa74d0131",
			"encoding/json/v2":              "fd15a7415e6520ea4e4e507b9beb72e0e2f8dbf542f0b22c4562092e86409026",
			"html/template":                 "0c3e0a0c737d647d72c7a8f8571131882c17f72a78c0a62568c6bd873a21f5ab",
			"internal/godebugs":             "e37bd6284b69a14411325e2cb52d1f7b8bbb3be24d7e684dc894e32f53185e59",
			"mime/multipart":                "3255c2ab43d62a15ce19cc0494edcd61f4375666c4393304b31c70d63a7810f6",
			"net/http":                      "3083c50b258b99e1b26ef5ceb4379bc4f702a773351c2a748df7fdb6bcfabea7",
			"net/http/internal/http2":       "f3fe08a1e8bb0425f1da0231bd046626d33d781ee00ceb172aec76f51dedba29",
			"net/textproto":                 "3be0df3fdbd14806727a6f55f1100b9edc953cd6c3ed0aaddf0793d2ca48c369",
			"os":                            "3e5fdacb612562c884fbde8a0fd4bde7859075b312827d8c6a9c727930c7dc87",
			"runtime":                       "429200df8a5604412eab8537fe8181c063b98acfaac5f9e3d4d706a868e9bb4c",
			"testing":                       "628e2d844a514bc924f1a5f3da6cfa1e0a2b92e6c89ae30abcab54bd6ae7526c",
		},
	},
	{
		Label: "go1.27.2-dst.15 cgo0",
		Base:  "go1.27.2-dst.15",
		Packages: map[string]string{
			"net":    "c80c61d75dd2dcd5aabe9241df9e929fea7d826edc702ef6157b0d47d50900bb",
			"plugin": "a7621873f1d13b052288814d5e0c517f88d748c857168f080aa5e51e8c29a921",
		},
	},
	{
		Label: "go1.27.2-dst.15 dst",
		Base:  "go1.27.2-dst.15",
		Packages: map[string]string{
			"crypto/internal/sysrand": "40f004f1405bd100aa2ba80cf760273b219d4ed917ef6ab8e5c916de5369f18e",
			"internal/runtime/maps":   "c1ad78efb177dfc5cab631c5200dae7445c58f3bd1fec1c6c7c24f7c948a832b",
			"internal/sync":           "068a9611d8af122a69baf9935a6bcde725954b6bf2487e6e9c0c828d92866a95",
			"net":                     "f56f472bcfc20b44959c14dd2296ed4a302acbd402631f2115cf629c63996754",
			"os":                      "8f3fb408d62215a303eec58fde46fedf4bac09781326df8fa7529537c91b1eca",
			"os/signal":               "675fe77339e1fb6936ff10e593910db58e9e0af7d9868f930ca9180c6fcee521",
			"runtime":                 "7fff93ed0dda4d0497d5b255fcc1bf45a311496098182d16b75b5d3ba6f6bae5",
			"syscall":                 "acddbae294709beb040bd65c3384214f8153535d1d8af3169dbd32c2581e488d",
			"testing":                 "2448a3af5e68c5f844e450d8bcc8dfdb8b458ecb00168b11b04954f318ef0c79",
			"time":                    "057b80e75745c0f88423489a53959220ef1078ae732e8dd5fdbf802d4cbec53b",
		},
	},
	{
		Label: "go1.27.2-dst.15 dst race",
		Base:  "go1.27.2-dst.15 dst",
		Packages: map[string]string{
			"internal/race":        "e80429a1ec958b17e616e45f07b6b6f6cd205a925896d2268f95cb19da585dc5",
			"internal/runtime/sys": "508268ec7dd881dad867d5d8ccfe777ee12c3b68de5e5c19051311eea63251bc",
			"internal/sync":        "3d70c31393537e325cdfda20117ffcc25d46c5bcf376caf3ec042212571fcccf",
			"runtime":              "ceddc25691af5c52e20541104d49ed292510b43a3c66e19e04e5378281ca91f4",
			"runtime/race":         "286c7e1ff0150cf2df8713e402d61c6a93c0f5f938bc3f220a6e35026782043c",
			"sync":                 "49313795240ce33d2176080d525f23378006f7c72607a523c32a164cf304a4f4",
			"sync/atomic":          "6f499cf4f7d682fbdf6ac4ded188a15d21c48854a80a04aaf5c08939f2c717e0",
		},
	},
}

// selectionDegradation is one toolchain-source audit verdict: the axis
// that refused (empty when audited) and the remedy clause the notice
// appends.
type selectionDegradation struct {
	axis, remedy string
}

// unresolvedSelection is the verdict of a Hasher built without
// construction (the zero value): refused, never admitted by default.
var unresolvedSelection = selectionDegradation{axis: "verdict unresolved: this Hasher was built without construction (NewAt or NewBracketAt)", remedy: "; a resolved verdict needs the constructor's selection and toolchain reads"}

func (d selectionDegradation) audited() bool { return d.axis == "" }

// notice renders the verdict as the one owned notice consumers serve:
// empty exactly when audited, else the axis, the consequence, and the
// remedy — text and verdict can never disagree.
func (d selectionDegradation) notice() string {
	const consequence = " — standard-library observation admissions are disabled (observation proofs strip and serving degrades to execution)"
	if d.axis == "" {
		return ""
	}
	return "toolchain-selection audit: " + d.axis + consequence + d.remedy
}

// toolchainSourceDegradation derives the verdict over the running
// toolchain's surface digests: a surface that could not be listed or
// read refuses naming the fault (the go command's own refusal of the
// flag set included — an unclassifiable selection lists nothing and
// is never admitted); a surface whose digests one row's chain lists in
// full is audited; otherwise the keys that moved off the closest row
// are named (bounded) with the walk that would list them. version —
// the go command's own, from the pass snapshot — labels the refusal;
// it is never consulted for admission.
func toolchainSourceDegradation(version string, d sourceDigests, listErr error) selectionDegradation {
	if listErr != nil {
		return selectionDegradation{fmt.Sprintf("the audited surface of %s could not be read: %v", version, listErr), "; the admission needs the toolchain's standard-library source listed and readable"}
	}
	moved, closest := movedKeys(d, auditedToolchainSources)
	if len(moved) == 0 {
		return selectionDegradation{}
	}
	off := "(no row listed)"
	if closest != "" {
		off = "off " + closest
	}
	return selectionDegradation{fmt.Sprintf("the audited surface of %s moved in %d keys %s: %s", version, len(moved), off, namedMoved(moved)), " until their delta is walked against the admissions and the walk's digests listed"}
}

// resolveSelection derives a pass's toolchain-source verdict through
// its environment reader: the audited surface's digests under the
// explicit build flags in the environment the reader resolves (the go
// command merges GOFLAGS itself), read from the GOROOT the snapshot
// names, the listing memoized per selection scope. The digests ride
// the verdict so a listing host can print the row to list.
func resolveSelection(ctx context.Context, reader *gotool.EnvReader, buildFlags []string) (selectionDegradation, sourceDigests, error) {
	snapshot, err := reader.Snapshot(ctx)
	if err != nil {
		return selectionDegradation{}, sourceDigests{}, err
	}
	normalized, err := gotool.NormalizeEnv(reader.Env)
	if err != nil {
		return selectionDegradation{}, sourceDigests{}, err
	}
	d, listErr := toolchainSourceDigests(ctx, reader.Runner, reader.Dir, normalized, snapshot, buildFlags)
	if listErr != nil && ctx.Err() != nil {
		return selectionDegradation{}, sourceDigests{}, ctx.Err()
	}
	return toolchainSourceDegradation(snapshot.Value("GOVERSION"), d, listErr), d, nil
}

// ToolchainSelectionNoticeResolved answers the toolchain-source audit
// notice for a pass's selection — the explicit build flags under the
// environment the reader resolves, the surface read from its GOROOT —
// so a consumer can state the verdict at the tier where the selection
// was authored without re-deriving the key; empty exactly when the
// selection is admitted.
func ToolchainSelectionNoticeResolved(ctx context.Context, reader *gotool.EnvReader, buildFlags []string) (string, error) {
	if reader == nil {
		return "", fmt.Errorf("closure: nil environment reader")
	}
	verdict, _, err := resolveSelection(ctx, reader, buildFlags)
	if err != nil {
		return "", err
	}
	return verdict.notice(), nil
}

// SelectionAudited reports this Hasher's toolchain-source audit verdict
// — a constructor-resolved verdict with an empty notice, one derivation
// with the rendering: the consumer-tier scans (purity, dynamic state)
// and the view surfaces answer their audited-set consultations from the
// same verdict the closure tiers thread internally. An unresolved
// (zero-value) Hasher refuses.
func (h *Hasher) SelectionAudited() bool {
	return h.verdict().audited()
}

func (h *Hasher) verdict() selectionDegradation {
	if !h.selectionResolved {
		return unresolvedSelection
	}
	return h.selection
}

// SelectionNotice renders this Hasher's verdict as the owned notice:
// empty when audited.
func (h *Hasher) SelectionNotice() string {
	return h.verdict().notice()
}

// SelectionAttribution is the verdict's axis — the text a tier refusal
// composed under an unaudited selection carries as its attribution
// (REQ-closure-refusal-channels); empty when audited.
func (h *Hasher) SelectionAttribution() string {
	return h.verdict().axis
}

// AttributeSelection appends the selection's attribution to a tier
// refusal's reason: a refusal judged under an unaudited selection names
// it, so a consumer sees that the selection, not the subject, may be
// the cause; an audited selection or an empty reason is unchanged.
func AttributeSelection(reason, axis string) string {
	if axis == "" || reason == "" {
		return reason
	}
	return reason + " (judged under an unaudited toolchain selection: " + axis + ")"
}
