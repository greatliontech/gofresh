package closure

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/greatliontech/gofresh/gotool"
)

// auditedToolchainSources is the one toolchain-source listing of this
// package: every row keyed by length-framed CONTENT the admissions were audited
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
			"bufio":                                      "0c98419ab1aeaa89e5bb6b56e9d1b2f853c03fecbb81663af70832a6c6ba4ef6",
			"bytes":                                      "977bdb2e26e8e51f86a288af8aff0f2e863b2aecac19029acc5019676f9b67cf",
			"cmp":                                        "dc283a80be6dc494f24be6c90c7fc1becb96c539e28b616f25dcab98fadabe80",
			"compress/flate":                             "f4550e39e990188bc39d59626d9fbb1c3bb1b7b77490642e258972fc9a7949bf",
			"compress/gzip":                              "e296c8de07984b799c6fa30bca2f3f69db57dfa52b2c060b612d28f2a0eaaff2",
			"container/heap":                             "476576d969fa462d7c0beb8e5017095598293fedb94801121cfb5cabf4edcbe9",
			"container/list":                             "817740a971df33a77aa3339347811588ae16b7562783a99b21304d4907b83964",
			"container/ring":                             "939f8059a6f702f4dc78fbf3fbbb73941921010ed71b499595f6b7bfd8ac8e0a",
			"context":                                    "7f0c4c44a3d5a6cc6d911adf8303bd84b331cd7f7b42fc44aeb0c2d0b1c8c0ea",
			"crypto":                                     "fdc76645fa4416a24eb193d9d0f9a8f64f933cade00bf07a4237c0de14906aee",
			"crypto/aes":                                 "24e8e2e7a4de5270e8625c2ccba73668782e6807f52bb269f6984d49f40ac3dc",
			"crypto/cipher":                              "37ad840f010d77518ba282ba153b26c813b202113460a9e9cca7a118a4aab64c",
			"crypto/des":                                 "9db3c7b6edeae2ed71ba5636c7f7de1cf455a469fb17f49d49d8b0168f76c24d",
			"crypto/dsa":                                 "bdd8b7cf137eb7296a9c08eeb9975a17f3583ca8b696951a53fb1f7c76c8edbb",
			"crypto/ecdh":                                "ec260cc6310341c42c9bc2946bbf22b18d2cf9cf6fc199cd894abd2c6cb1bb88",
			"crypto/ecdsa":                               "c29a8b1dd66b8fded315aa3a4a182182e8291fcb26598d24b2fd96d18087a5ff",
			"crypto/ed25519":                             "2aa0e4ae28222bf0f1c8a3bd5a790519a443d2ef70d029a923a5d3ccf50ec91a",
			"crypto/elliptic":                            "8093046212d86c4ff2b3b7cb09a0ddf76d4197c6c606f9ee900b9a3b62a58898",
			"crypto/fips140":                             "3f7eb7a5f715ecfb19eaaf553b090327799fffdcf5974e8021dff4ec05d8fc5a",
			"crypto/hkdf":                                "d5b15d3c347fac0eda04d531686693b2b2a2449af24f785fedbdfadf3c6878e5",
			"crypto/hmac":                                "b8f2db201e8ac4cec03aaa5aebecafdf465e767e9dea55b7cf724f110f8c52e8",
			"crypto/hpke":                                "8f198af017eb0ab3ce0e1e28e5142ff6aadfe2574caf7ae17eb52fdf4c700ade",
			"crypto/internal/boring":                     "15dd92dab23cf353080c36d0dd4454ee55c5f9a0325704e4e1e0fc8599d767f9",
			"crypto/internal/boring/bbig":                "8b0d1bb2fa575b72cd49bd6d15560438c64a18f951faaa2c17cfd12835dbb326",
			"crypto/internal/boring/sig":                 "c7f2700d31a727be2b603a5e50d032a1a86e3e5ab8e858956af5f3f1c9ec9569",
			"crypto/internal/constanttime":               "249304b5ac64c355c9681b17049f09da0cea2e4750b7547bcb3f035b9a1bb673",
			"crypto/internal/entropy/v1.0.0":             "30b7086d0544e87f1d32a4dbcd20ff00f71de9709a9dc82924cafebe0f6364d5",
			"crypto/internal/fips140":                    "b2d3e54bd4af73bb17f7d4eab05049c5aeedfcbd70805a77f67c7bcbaacd53f3",
			"crypto/internal/fips140/aes":                "33350e18661f6be33524b5bd4bd3f2705091fe5c01874b0e96ab022d3b6e80af",
			"crypto/internal/fips140/aes/gcm":            "d45db01a8075e2eccd2c6d6dbe4e510f5999d0648521b9ee78be3124f94843ae",
			"crypto/internal/fips140/alias":              "0749428ce8cf1b1521be370cf6ede7c9ab1ac576e36a5345a81d304646783097",
			"crypto/internal/fips140/bigmod":             "d5324db3f8936d20944d2c09b03e0686b18df8b00bac6f71e624495d5a13bc24",
			"crypto/internal/fips140/check":              "b44ddc57676f9c89f1cfb70e0d7708ba309e1b8062f2baad4d4fdc2f1aa047bf",
			"crypto/internal/fips140/drbg":               "5bc8dd0b6e958818519c8747cac7b106446988e411d147b65b5aa059877ffbb3",
			"crypto/internal/fips140/ecdh":               "e425c372b149ab21a38e9b8860af7b1faf0e628332d68f5eaf2a8a227890a071",
			"crypto/internal/fips140/ecdsa":              "4d27d419c8715e22ea6b05e5c1935f0e1e5cdea33e285d79a4e936c85f9f2ca4",
			"crypto/internal/fips140/ed25519":            "7ca8220d537de657e889d361b21f6f891b7cd5a968a47178905009e8e9a3a9df",
			"crypto/internal/fips140/edwards25519":       "1026a6c790f0a8ea41ff3e3c9070c7774ed2089c5d77fc05b9dc5c91a07e306c",
			"crypto/internal/fips140/edwards25519/field": "be3bd6e92b3b440cf2c93b2f6ff384a22ff30aac0449eed10cc99f4241dbe79b",
			"crypto/internal/fips140/hkdf":               "f4633949cd14e7cafe02abfaa04424ecf108477be96565fe08e32825c0bf32e7",
			"crypto/internal/fips140/hmac":               "59697bb431dc15d907a74e6fcd56e0c7326ba51452b673d594e5b19e58f5a6ea",
			"crypto/internal/fips140/mldsa":              "8c8fb32fcca03741b17316e339ed31e69b54b0765b2e61b3f694d6552e2a2e36",
			"crypto/internal/fips140/mlkem":              "78ea1c4da48ad4a007e68605f3c5b0509ef6050785ce39a7b6c7daa7869e97ed",
			"crypto/internal/fips140/nistec":             "772dacb3373a46920d8c167b0b6a069dbcff9124210d9bec92e76263e8c7a684",
			"crypto/internal/fips140/nistec/fiat":        "fceb83dea4bca87b69ddab04b1740aba82b4c435f91d20bd0e8ce02b63416ab5",
			"crypto/internal/fips140/rsa":                "d215e6fd50c16c5c1c481f78fb2fae9d9cd8585b4d0163ef43d3a321b15a5406",
			"crypto/internal/fips140/sha256":             "a2297b3dbac653f7e280784c238b29d58a0400a30c5417c556d2b8c11abc866b",
			"crypto/internal/fips140/sha3":               "5b061528503a063c9037ccb979cce881500a6a1872357bef0441db74bcc03f44",
			"crypto/internal/fips140/sha512":             "0490ba44dc4362db67832589609cb54d10636699a14276c782887b7a1162cfb0",
			"crypto/internal/fips140/subtle":             "c303cc0e6f810feab96c14a3f1771db9aa012931411b7fa34d8ab9fe6cc4853e",
			"crypto/internal/fips140/tls12":              "7487580e9e8c11dfdbcbb21cf595ce0eb7b42974ab7173748f27b320f6e70919",
			"crypto/internal/fips140/tls13":              "34bfc727d62de7e9307516b04e5c0d400b7957f3b15ab48d75bbaac9cc3e917f",
			"crypto/internal/fips140cache":               "baafb8784f8d18a611c4a64963380be93a81c55bb1b73ddd0ccde5c9be8298d6",
			"crypto/internal/fips140deps/byteorder":      "99e5cb993daac430d08fa9497aad748447ce9cfdcf5eddb9d9b8ef6fb7560548",
			"crypto/internal/fips140deps/cpu":            "86d3a48a7036836897c446e1ff1cfd44303fb93ca1421721df9b2b74ea5a2ef0",
			"crypto/internal/fips140deps/godebug":        "afe6d4fe19381d52443c1a0a6858f44ac904951261f831311aa0cb169d9511b4",
			"crypto/internal/fips140deps/time":           "4b1cf031835ec12cc8a7e1e98e2b50315d9143633d7dcaa0675be8916184b8df",
			"crypto/internal/fips140hash":                "eb8f4348bf0e5b4fbd4d67fd379bcfab729b83ce322d33a6a4e29f73b61a1c46",
			"crypto/internal/fips140only":                "c1217797fa23558d428aff9801584551c69994d5dc902b28d6454fe7cdb04bcc",
			"crypto/internal/impl":                       "a5675e8c105cfe45141e13d5f23f68fba58d52d5adb4b707c5bf35596a5e1759",
			"crypto/internal/rand":                       "f99f00e662ce1329db9fc70f15dd411b2656149b03e02e73f9f59607419416b8",
			"crypto/internal/randutil":                   "7ff4509a3fbf579244584a1d06254489492381cb3b9c6ce19c678fd04f5a8be3",
			"crypto/internal/sysrand":                    "3e153addf035d4cfae0818e7bc41fe69d18a4d1d2338871d8668a99e4f2933bd",
			"crypto/md5":                                 "e795c354ff2963216accb1927d08ad2a373b5cd660ece118be5293c202fb0adf",
			"crypto/mldsa":                               "9880a7c86f6f5fd6edefdfe11e9342edc879347140f51ad46e838c284799ac23",
			"crypto/mlkem":                               "b4ffc0a05a06130bff8618d9a8fcfede34e0a488d41873f9e73dec98aaf12d8e",
			"crypto/rand":                                "5028879bfee8e0fcf90b1aa2756d181622a18f80bb7ba7f9340d07d5ba5c471e",
			"crypto/rc4":                                 "b9f41d2604454d736b3e7f8dc88fc8bdd371e8b3dbc727cbd2d9bf5cfaeb8b62",
			"crypto/rsa":                                 "0c8e12cd16e6cfd235890ccee890298bc6421ed729509b3ec79671b78faffd0e",
			"crypto/sha1":                                "9fd858ffeafb5767ee8a4933ad90e8e743b6d2f78a4c0d6ebd499cde422eacac",
			"crypto/sha256":                              "12beb73bddb13071df9d870e655f8b92ba43ed8018be43eaced29056b10b3228",
			"crypto/sha3":                                "1fd1756bfd30854cf62f095e0486ff45195e7b19b19c081cb7cb7fe43d1e419b",
			"crypto/sha512":                              "83eb19ec565225751a4acecae1177e011947666e07ed627c1d2faaf6f61a4a89",
			"crypto/subtle":                              "e14c24df640580c4f9ac69639f60c1a80b118512c22f37bbc7a093960364070c",
			"crypto/tls":                                 "32d0c1f37e80060d26fdd18d3746cbca520c5c25d688dc35951929b30c9a6185",
			"crypto/tls/internal/fips140tls":             "0599840b8ed60591f1a7eb6319b95d2e7658ca286183b1c19eee2868d1b63bab",
			"crypto/x509":                                "00f5b9141525218412b0ff334c6d9b4fbc0a8c97dd8ac3512f47b8fb66025a02",
			"crypto/x509/pkix":                           "45415cd0d890cdf760062be83a6809db08e9818584dbd95114acf2d40a6b2c80",
			"encoding":                                   "ec9404206998ba1b5d22a582ed135015a4ee52c9446ac586df902539c9744d08",
			"encoding/asn1":                              "f9a06e454e85a83aae13536c8320acf77869c5e5d786ccb14a5f97f5fd1f4633",
			"encoding/base32":                            "5de63d89504af0e3e7f51d5acd7000aba026d6d9e26bd417ef1d529a83f7fa5b",
			"encoding/base64":                            "ac545408b8bd5cd13c66065eec9529ad54bfa3bbd5ec3d905c13768b4564b001",
			"encoding/binary":                            "e0cb7a95c4b41ae5790e8d98e52daac11d12a134d2b1a7b4e00eb87adb6ea05e",
			"encoding/csv":                               "9e599dbe86daa02b49bc8db3c2eb27519405ad1ac6cb4b36fdaaeb4322663e54",
			"encoding/hex":                               "9999d17b22cf7f0f79742b23c82482db5120c54e6fb73d5ce9359457d2c1d168",
			"encoding/json":                              "ef74513e5827e9f8dc3bf7811bf2b3e3c5f172842f9af6be0211d8e3489b1c86",
			"encoding/json/internal":                     "e0398289ed7eda12e71b2e44653b6bba82725ec3d6f7b539f9ae2ad390833a02",
			"encoding/json/internal/jsonflags":           "c71f32ffd0756d3d13163c4f6b5b779269208f17dc5c7d6f4df51b7093bc4495",
			"encoding/json/internal/jsonopts":            "f6c1e3eee18c0e2728a1e3c751d3bd7a29b0de82210dc9056a93adc302a061c4",
			"encoding/json/internal/jsonwire":            "e7ced7b8dcd01c550885af06834f66215fc488021c3fbdef1f3a45fd20d8d517",
			"encoding/json/jsontext":                     "0857c5a9ac8a1c4e8bde5202e7da5b4190cdd6d5175f6ad49adc5cfe83ba381a",
			"encoding/json/v2":                           "8b4398af1be2c8f32e2ab34213c3940722bb67ca214cac5433a8a8a7eeb8138e",
			"encoding/pem":                               "34b192182dd4d662907252a12382de8390c238606947e5c6e33cba567dfe49dc",
			"encoding/xml":                               "28acf716d57504527a46f237af71f7b96caf284455aad4bf8454807be071dd96",
			"errors":                                     "f5dd9d0a39d27823666c83e2e3fa45b47bf5fe995637178ce9014765172d1873",
			"flag":                                       "23a8dec9fb120ef713d5f566187fe7fa138f8384a755bca971c0904447a06c2e",
			"fmt":                                        "f118b871173d49fdc4fe39938e5bd013d56975695cf504ef956fd3cd4abfb1ae",
			"go/ast":                                     "aee150962cee264ca95e673a25e187fbc45ff681cecce64021311ef79100696a",
			"go/build/constraint":                        "f50c616b141df742a48bd5b02bdc7a898cdbdff071ad9d6ec24c138627c5e428",
			"go/parser":                                  "805b2ee0dd1f26038fdebe1c521c33e01ea2caf5920fb213770ff82c9d0ed94b",
			"go/scanner":                                 "ede73f262edd83cfbcc86e9620c9881546ebdcdda1ad8eaba04934205b8d6250",
			"go/token":                                   "97ee2f797fbf8c109675952e56dd77acbac8f0ff0da520a206d57094ff3c49d2",
			"hash":                                       "a92ee1edb59eeddf044f1144545b7a853e5e7c01c402e1cddbea0778d2bc02eb",
			"hash/adler32":                               "bc5395279d81fdf48b51012c7232722ccf8f04edbdd140eaee23cedd14e3ef40",
			"hash/crc32":                                 "7efb3a30cd1e19aa482e6decbf853b9f592d14d4b3e192644dc32cd25869bf6f",
			"hash/crc64":                                 "6ea2fe20e39b85fe0375ef151032d708a488f7041ccacfcc6c7bf38c6e745cf1",
			"hash/fnv":                                   "b9cfc19c02b69a3406b30c01a48b8b4676bc5169c63f01d566f535f2c7e04b9d",
			"html":                                       "0d62169cda3217d450b58a313baa5ffda9e39f4c1e31caa680658b770bd422fd",
			"html/template":                              "4010864305607f79d74fe68ed036856a0dc4f126277f90e4ede6476a019970d2",
			"internal/abi":                               "2b2ec91965114547fed73a871f238a811985633acf413871cd8b97840a0fd761",
			"internal/asan":                              "50a2f298017f792dde5d44b06696bc0a4cede6f8c6990ecf6105dbbcc1eb2b96",
			"internal/bisect":                            "bf25e934ec031e86c874e52f87d196921e521e67a0a4b4957f050c2f6fdc71dc",
			"internal/bytealg":                           "8c88952a355f74a1a838061c75255a879297a0e520a2ff985800a8a85ba71d1f",
			"internal/byteorder":                         "01fcf6b1137a7c6950ff30bc6d964500e5e5bcf5490232ecb34b7805e2c95711",
			"internal/chacha8rand":                       "0fa9a401e29c2cba12ebd65e44e72d42a975babf78371f6bb44397190f0461d2",
			"internal/coverage/rtcov":                    "970cf67680b53288249d09f92bff5cca930bebe3ac68d5fff020a88dd807bd25",
			"internal/cpu":                               "d4331a1a4174699ef5251dfda2c3b8afc87eccdbdb1ec7ba9ec82678d8d1ce8e",
			"internal/filepathlite":                      "36519030c436809d79eb5428094542724e4402695abe793fd22648c2f62674be",
			"internal/fmtsort":                           "a43aae799be7a6e466f12eb3cfbdd9a96b858def2adaed42a8045d71beb9a758",
			"internal/fuzz":                              "1aa66ad8a736ff95346831fae13ab9d1e4cf3ba294217b279e2702e3721f0f56",
			"internal/goarch":                            "9f281c9e44b92500deec3ed460f8a0b6f0e83ca5b86644525f0384bab4b64c41",
			"internal/godebug":                           "b317661f8cebeba629c5a1812ecbf55de6b26d7994a4bb77b5ca2665daea6f03",
			"internal/godebugs":                          "1a6ee96dacbc013256dbbfc8b959274c8470c2feb9d695b942d70e0fda284ed6",
			"internal/goexperiment":                      "cfd71a6390474cd92f384d84b736addd027e1f821cbde23b62b579d1cc48ac5d",
			"internal/goos":                              "1b4a792505bb747afe9604cc84d04abb3ee2413f1adf8ee4ac0af320eb968fd2",
			"internal/msan":                              "67e563a26c249bb0989be5ebba1630a42059b12e6a54b7632dfbb562927cd22d",
			"internal/nettrace":                          "4b10ca91a40d7092082c30ca5d5515faaa64d400bf536d2bc1df5ef5a2e6b57b",
			"internal/oserror":                           "dbbebaf8c78ca381f21bcc144f7ee5992163124a7151566416633baed9ada862",
			"internal/poll":                              "0a830d322e3346ad33c648a3b1c21389152df5112900217020643d268ec113ea",
			"internal/profilerecord":                     "e33a7e70fcbec2a00f3ae22c544e886f4c110d89e3a39bea613bd664b1e43af3",
			"internal/race":                              "d31440f399c3ed8c00bd7c1685b607192e83d37f3b601d2c00eb89c701ff8b7f",
			"internal/reflectlite":                       "8d8f4f06c5b1466ca4a974aefb2a42843704f426d39b01187a50df39738c26db",
			"internal/runtime/atomic":                    "25aa54c6b11930f0bde09369c04bb229a944e5b2b78ee1adfae2696678db7061",
			"internal/runtime/cgroup":                    "988c5792f95f870dcf81080bfa754c395f605050971d8eb0796c07d15f048660",
			"internal/runtime/exithook":                  "a9cd9ae1fa4e737a85df58e220774f231d1df4231372a6642f4957b12cae99ae",
			"internal/runtime/gc":                        "270ccf36ff89c8c37d9b9505ce668a0f45abbe832bca90181fac29f40ba467b7",
			"internal/runtime/gc/scan":                   "6e6f8318986ad3c6b88345433e900c68097823309bb7d3828d0885d6f31c7a71",
			"internal/runtime/maps":                      "b0d06cb531b5a917b3ec16b35ecedda486200af87e9607b60daa476f445e024f",
			"internal/runtime/math":                      "824407c504365ebdc4a48bfbd9067c1e9113d0632fc6241f7ffb82d95cd25056",
			"internal/runtime/pprof/label":               "96e868c1e906b85ded49c4462568193a02402ebad719e2dd8cad2fd8350e3e92",
			"internal/runtime/sys":                       "3b6984ab8d905958fd792529c6cecbbd9041197fe40ac882f96647617171bc6d",
			"internal/runtime/syscall/linux":             "c53b0335788b19046cc9e6971eefba3dfc2e5a33b5229dbc463d023b41f1c579",
			"internal/saferio":                           "987c9c5ca7d93dd7e74120e003f002942d0a3dd9f54083dd818beaca36d76a86",
			"internal/singleflight":                      "5c08a523b58a0627ae9ae6471b4a2848ca22c1814edb2a6a4442b45f642d5273",
			"internal/strconv":                           "94443936e54aaf7e9ea1bfda1a42af5fb825a39b0c5e08f31c079dda49d70efe",
			"internal/stringslite":                       "5605bdda40e2f9e41b2bd4675c7eebc2119ef8172a832c54f4e88477644a941f",
			"internal/sync":                              "855c2dc30bf6bbea975566c5efd75122e4f7fe6e65715a4fd33148d267c40525",
			"internal/synctest":                          "368f4f77eda949a6ba6e8b83291546a371a0beb6dc759abe9dc58c1ef1b74986",
			"internal/syscall/execenv":                   "15897bc33b985e1bfcbe50e28fd6e3f26e0d7e858643dfb4fee112a981820f8e",
			"internal/syscall/unix":                      "c41241c6364690c1937d1095ceef440b393e03c4d3d0026f71d58effb9da6bda",
			"internal/sysinfo":                           "74743f4a6c6c50131410fcf3dad058937bbe57cf494400e607759601382a8477",
			"internal/testlog":                           "195c0922289ec0bc19cce65c57310cddacb396d18d51d879a68344e4e75d328e",
			"internal/trace/tracev2":                     "d1de597d3d76600ba64b50d25b61db21092fe19d7671d73ec6ea38ce593c4890",
			"internal/unsafeheader":                      "d9269a8ec5356e9d07fb8174b432545ada7fad15a468d21539d67829cfcd5365",
			"io":                                         "43a19000898876c165c91e8876998f83f697faf932990d07a4ff58a0e955ec86",
			"io/fs":                                      "6e9becf59a521e79e6add2e17fb4df637c2604b69ce9d339159df04981d3aada",
			"iter":                                       "f336f0fcb790a88a632ec512346d90b43899c507f8e590b6e39b81d44b8dac94",
			"log":                                        "142c99402d62a0fe17b8fb24e9c15f4cab799d15d2d2d035d3b4d46476b73c0f",
			"log/internal":                               "18c1a5010c46be64c525295aceebe4bbf775cd6a3b34f14938cca747b0570969",
			"maps":                                       "70327b48e6ee357f0d4f267152770ea4b3337602093707f2bb050d21b1267778",
			"math":                                       "2d84fc8df2e77b01516a3ad745141de5db8852926d462e333c55e4239229b481",
			"math/big":                                   "0cb4b420b419460edc7fe31e919099bdfc17977f7645fee844319aa9c0d596d3",
			"math/bits":                                  "6166f76b3b216e1053c05e585838e877f2f53ca4db00d47a1e97729e570f3ffc",
			"math/rand":                                  "1ac68b13594402b3a93373262e676d84d8eb8c067bfd92de729fed0bd83d82b9",
			"math/rand/v2":                               "46cf587e3a7a179cd117a779f89409bff70bdb1285b43e13505e2c84359ddd26",
			"mime":                                       "5913bf5a96f00840b423cc1cd7af86b96b91713e587e8ec61e109757f86d1081",
			"mime/multipart":                             "2b0e5fbeff0cea4befe755fe766ef88d5110a59cf7efd6f6cf29cefd1256d910",
			"mime/quotedprintable":                       "dff27b18ac1b86408ccde0c446b9aa4fc4e69efcfa20a4c57aedeb466ed5f49f",
			"net":                                        "d596d8869fde909258816cca6ec13fa914343860ef166db9d8ebffeca2ebfc9b",
			"net/http":                                   "e1a10da02ba53a3adb41567dcd987a8da4233cfe2c220b321077838efa7c265c",
			"net/http/httptrace":                         "1c77456a0a6a74420a86ec9f3959f1f5ddee02ed6a953582cfd15e8b4a988e45",
			"net/http/internal":                          "24403897f57a7cdb0e461a7dc1269747fac998fdbad42555da22ed84dbb6778a",
			"net/http/internal/ascii":                    "a489954b61f429baeb24e91e683bc302d23b7a083494a0d88432c86df342df17",
			"net/http/internal/http2":                    "406af8a8092e5d0597afbd9381fd016f550d21a1548f89e866adb3bd4782f495",
			"net/http/internal/httpcommon":               "a88a222b2349ea31f41832fe4bc3610bfead5482068e8764297fe00f8f3ae2bd",
			"net/http/internal/httpsfv":                  "697514c478b782c03c1be5b93e6ccd71d47627916e544602ef249c49d8d661a8",
			"net/netip":                                  "ea86b5ce21dd0763995ce32549ff78c5cccc3fee4e7104849e4bf44d22bd3b6c",
			"net/textproto":                              "83e673b936596e8e97fb3aaa9167b0107d80e273a2eb8398fdaff04d814d6321",
			"net/url":                                    "e55684daa5ce5dce65cb872b6aab0ccde4937baf0ac192557e40f11d75493c52",
			"os":                                         "a06a6e30a64adabb3625cd41de20fafd260efd57b505dfbb924c433c46afbeeb",
			"os/exec":                                    "0c3857ea4675583f0970645b8b875b70e433ed1f67f06080445311febfe979d1",
			"os/signal":                                  "35ee4ce3a3f489faab3753768099ec7a305b002b11903410aec3189f7a4b92e8",
			"path":                                       "64e52269e142794a1409f5610203c94215e819dca52b55b4f18f63b414eef397",
			"path/filepath":                              "01f5aaf65357a4031d06aef8d38fc7def73c0195be8418a119885e886a1daf84",
			"plugin":                                     "ced2d0c8554e34bf1308f3cb844d9576858a790eed1b46103ca67dbbca3d8d15",
			"reflect":                                    "dc818a943e9ea97db787ff488bb7d23354b1474c6ad3818138590f1d7fc21b1a",
			"regexp":                                     "adb1338e44eca198b8af4af244dd3cd38e73a2f7e33fc4e0a43f9f933112bf88",
			"regexp/syntax":                              "a9c048d6587169213134844569cd91cd56e2a8c072c52f6ae5616ac86db02b33",
			"runtime":                                    "88273468864a726ba62c9d5fb30c5cd98cfb5b1ca1ec05e8b3af55ca55a9520d",
			"runtime/cgo":                                "4dc312bc9889e162a42af1be768820666212d7ff7bfb67338f44fc03e1f0b905",
			"runtime/debug":                              "9f9f04b0c11947a1dfdfc0ae139fb9ef1d9c8f3ced20ccf9c0d80396e5b7754c",
			"runtime/pprof":                              "3406bf081ca76fc37eb2bf25afd2cbe26024eef8dba383bcba917e363b55a17b",
			"runtime/race":                               "7226cd97edec0b2835f8ef707f20aace8861dacbcaea5be62b917a65946d4a6b",
			"runtime/race/internal/amd64v1":              "e1fe0d6469efe73bd97a0794ff7664964c26a7c317309bb3c6a797861772f6ed",
			"runtime/trace":                              "16e0e5c3c92d97c1e7d6520821cfadfacb7334edd3e72333c484cd16b9371b4e",
			"slices":                                     "44f339fbdc01fe5a40e6a2e7c9ac7266cdf3df0524e0462a3f94bcbead0fba5b",
			"sort":                                       "a744dced6b7de38d92fcf257f32b524ef359dcc9f6923b28e4f90c3266264cb7",
			"strconv":                                    "e4536e2d7e4ecf8809fea1b0bf2209fbd26e77a8b3ac9d49ef744480e04c039e",
			"strings":                                    "6d1c1e4640651dc9675d1271fab4171bcff391d3601bfa9f2c47138c3bcf2cff",
			"sync":                                       "4c9ca1171eeaf35a6c067f98ceb39a71cf9f6177be5b2912b25f7da1bc969cd3",
			"sync/atomic":                                "42aa2867552d5c4d951a0143bc44b61c2deb95791a262cfe8f722db7bba6f092",
			"syscall":                                    "b12d91dce8fe9208d8dd75c114e7b2f53dfc6261fb3f600ce19add4467fc2a26",
			"testing":                                    "6f7310eb4af8cfb87e1fab4c7d8fac2201cd768bc0b7b08495a814f5e68038c4",
			"testing/internal/testdeps":                  "ccbed91ebc3d33b7ad08d18a06a8446b253c3d4f1abf698e2e02a4d8542e0350",
			"text/scanner":                               "47c0a730339e5afb232e711a611e2dcd9a09c65617a0d836344f3b51241d3fee",
			"text/tabwriter":                             "4a0ab93165e6d90dfa00dad95b5dc248afe8b6e1b3bf02b8cc52aee59238aa1b",
			"text/template":                              "714256cc43a99dcfc0bcb6ab4a0e5c5d93c757ebe70d92aa9337e854cfb502ad",
			"text/template/parse":                        "646dd36e170ddd59d383fb7b276ff164f73846f3c73b77ef2e2c12e19a5349d6",
			"time":                                       "311e9b7101a85a1faddf34c4c24d949a4e3d8be3313f01c246a5ff2e249d83d6",
			"unicode":                                    "6c45f38c9f5f380d17d350ff0189cd51e530b44a902fcfa448d87bba1d213438",
			"unicode/utf16":                              "3fa2e0a406e07f4073aaa33a902f5815956462a6bc4205dc0d9172a68afc3690",
			"unicode/utf8":                               "8bc7e1fd17fde6a50f5bdc86c4ae1c237e94163252ced31d4c1c6c8509399345",
			"unique":                                     "fd0fb02abef2ab314035632c4170a1b03da73749cb7717b21719d554d56a4c9a",
			"unsafe":                                     "55e212d1f92a9f6aa66f52c3f37226e32cfa752bae520e6d2936b4d52717156a",
			"vendor/golang.org/x/crypto/chacha20":        "934cae456ad8006ffe3501b49f907223916729706121082b2b2787a1532461a4",
			"vendor/golang.org/x/crypto/chacha20poly1305":  "24a713125226bf7d74a0793e157d1e651b0576a8f2bef5c6127f5d901e4dc444",
			"vendor/golang.org/x/crypto/cryptobyte":        "81af80a38704dda027f7d09fb24240978e5fb7f55e49327388427c3bd0e44e80",
			"vendor/golang.org/x/crypto/cryptobyte/asn1":   "7dcb400ee33c22e1bc726d50973c52dd83584f588cb17dd72c526286591ed6d1",
			"vendor/golang.org/x/crypto/internal/alias":    "b70802e740c7cf303b6cf31b871c50269f9a1e6e6ad719888f0b556ab25b8412",
			"vendor/golang.org/x/crypto/internal/poly1305": "6fa3f39d5e1c6961d0216d305c93cef0fe81b4bdef18444cc77001eb10e2519e",
			"vendor/golang.org/x/net/dns/dnsmessage":       "4576e76e7ddd33187e2a2e568c94262f4a3d878dc1d593812e2dfcded5b20faf",
			"vendor/golang.org/x/net/http/httpguts":        "26fb80158f725550b66623bdd69360c2c7ec2ea02f436900dda10332dd80dd2d",
			"vendor/golang.org/x/net/http/httpproxy":       "7ae2b7a19097e90ebe45e3c2b5f34fadee30d5f21c1bfdd90c5f1b0b8b5d4a0c",
			"vendor/golang.org/x/net/http2/hpack":          "b340333b29c4ed7bbd0c09eb8adc199e4184f9346b11871f2d3b9c86e37c3697",
			"vendor/golang.org/x/net/idna":                 "7c0147a1226f34551e7bc098f76cc328ba1e983ff7d1c55cba11d2e0ec9396bc",
			"vendor/golang.org/x/sys/cpu":                  "61ca4b6f4d3f59326c7d4a155104f7d51afbc9f756ec5bb744e0e0b52d1a4cb1",
			"vendor/golang.org/x/text/secure/bidirule":     "ad731ba2686abad7fc152b45898824c7858beb167ad4792210f97c951bfc3f2d",
			"vendor/golang.org/x/text/transform":           "6f2394c32db2c404b4a80adfbc57c4a8bb708d66574703bc6c576ed6f3ed8a23",
			"vendor/golang.org/x/text/unicode/bidi":        "373821a9872ee92c487c965fc7e9649aa18a7470f33997083c522ecaa7ef9f73",
			"vendor/golang.org/x/text/unicode/norm":        "7905cf51d25f5fbd9a0bd89a715501b0b7b36cf496e674e25d87375a5e3fd502",
			"weak":                                         "7af6e75c03da4472bacdef80c7013353d4cf927bf15cb0c1e86fb0e8811e481a",
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
			"internal/race":        "8b73d1da46a77b9156aeef8ee93e9bc760417131f993a0bce489e626e32a3920",
			"internal/runtime/sys": "8a4de7b36d428a5ae5fcfd24b979bc6778c60ac017cf1dbbccd938b6455067db",
			"runtime":              "7a2469bcd22477dbdbcf5bf9ce9e57976964c2fef6252da36e0703854a3b558f",
			"runtime/race":         "7a496110fdd6a0c6dac1b36937f1c7fde51d51d0de7b87f7dfb2d9cdc0cc142c",
			"sync/atomic":          "11ce6b22151ab4e36738fab846491e2bccc453041156333fc7fa36c7b9ec0f45",
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
			"crypto/internal/sysrand":     "ad2bb8357c2bc49fb8b8f0afe84c7ab6c9cfe574101fb3c8924c2de78fd86662",
			"crypto/x509":                 "4902029adce78e00e32519204f857c42788a96c2e2cd389e3ea6ac697a02a112",
			"internal/bytealg":            "504de20a9081de8e43cae6594f29ccc3719b1ced26c29ae96569e294efeffa17",
			"internal/filepathlite":       "48fa36289d7a038a0f0ab46de8bd07810c5f1c84587b7d1d60b4fc8df308f31f",
			"internal/fuzz":               "b9759db740b8b718df516bf3c7c3395d3b33be1767e324322f815889326d4d1b",
			"internal/goos":               "372e0c194cf8f197018df3ce8ef923e9ee7c1b2869fea23d86af6c26c947ef0d",
			"internal/poll":               "d0168a997fbc63a5ec7fc80d49c5c0ba5616ceb86c8383b9a3058ca678a3e5d1",
			"internal/sysinfo":            "fb073589be65508e2564fbcf0135ac7e078d3e0a2f34417ef06bd76999295963",
			"mime":                        "60b87b497531786f7a1b1eab3e67d426ac3167723ae8bd8c7c2954babca1cda3",
			"net":                         "d46a4946831d04a9ffbd1f63ecb5b58a12d741b6706762a5b7e636169682de54",
			"os":                          "0c7e6ee07be03042f6aafae431541b6c177d4571f1f8a9a65aa0ec0407abaecb",
			"os/exec":                     "48d7ad61db453162deaa352e98e1dbcb5c05f355b5abcb85b84639092e38dec6",
			"os/signal":                   "7dcd82a18ceaac32d9235cc1ebe688a8e57e47626253f55f10faabdb686c3a9f",
			"path/filepath":               "01eceadffa489ea0064a5c9301a5378027d2c6ab1b8d5f377ce041e4724e2169",
			"plugin":                      "97933b973cdc749095ef6a6ca7a98b0adb6ceca865351e0b3d4ed66fe15679a6",
			"runtime":                     "c97dd830cb93c49e3d6e60f4691c49e01d73a068a705d4d882e04bf0b9b0513f",
			"runtime/pprof":               "8d1f2524a6d4519a87f302b532234e7931ed532accfad1649f95bf4c7a70c304",
			"runtime/race":                "17f35321561e4de4c1218c53a645899977a52441463b3e9bea41ac9d029f8a56",
			"syscall":                     "287ffe5f73babd870de5c4767d37030fe888e4e720c829c1f4e25c5de7c155df",
			"time":                        "a059f57280b98b5bdf24134b92b8df5cc906f113f01a1fd36fdc977207c2906d",
			"vendor/golang.org/x/sys/cpu": "1837c2c3644543e68793e1d1cc9546b879007ab8cdc9493452ff4c4a92ecee4e",
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
			"net":    "a18b2c37538467a94cda1019585467671e2e1136c3df22f41dff58a072453956",
			"plugin": "97933b973cdc749095ef6a6ca7a98b0adb6ceca865351e0b3d4ed66fe15679a6",
		},
	},
	// Stock go1.27.1 (the dl tool's tree), over the dst.13 chain: the
	// ten keys the godst hooks touch, stock's bytes; its race, plan9 and
	// cgo-off rows over its own chain.
	{
		Label: "go1.27.1",
		Base:  "go1.27.1-dst.13",
		Packages: map[string]string{
			"crypto/internal/sysrand": "b04337c2e04fbb94d63b493dadb99fd7828d9c752183d3de72fd1cb3941ed38f",
			"internal/runtime/maps":   "9b042d1ce2e2c30cb060ac5b9c429017db177bb9d68277555719ff9eeb72ff01",
			"internal/sync":           "baf8169d3455cfa906f61d8a9b7ddf50bc3ae5692fe9efa054721e0e8d320c67",
			"net":                     "2590e72d902e775b7b7a3b379c5b1d4789d1cf0e124a2df9abafadf7fb7f692b",
			"os":                      "02e844a8aa7d9c1316ba503d5da7315b969d53feac6338896b8fc9c41b885cce",
			"os/signal":               "066049daa360d539529693e7a3cb41164b65fd9aeadd27bea0f960e76a7ef03e",
			"runtime":                 "0476d234ea39dc2b48c14639c4752b22c2f68ea9313046bcfd3e206b808f9145",
			"sync":                    "784baf5996cf5714fe426fb78bd47a0d897ee3768e16155af745cc0f99af7b5d",
			"syscall":                 "c1c61abdce53a09010a87c90151935a170b659acb7b575c6cc8262672aa49a62",
			"testing":                 "f2439dafc00e0848a9ce583b38d309522b3b08adf64531458755ba3b8e73e0dc",
			"time":                    "d71b2522ab106124e1f864e251bfc302272bb4bdb7610862f18df0166c2edaae",
		},
	},
	{
		Label: "go1.27.1 race",
		Base:  "go1.27.1",
		Packages: map[string]string{
			"internal/race":        "8b73d1da46a77b9156aeef8ee93e9bc760417131f993a0bce489e626e32a3920",
			"internal/runtime/sys": "8a4de7b36d428a5ae5fcfd24b979bc6778c60ac017cf1dbbccd938b6455067db",
			"runtime":              "638e64d4290cd7eeab8e91029cc9fbf82911bc0417daac76c73105b825686d9a",
			"runtime/race":         "7a496110fdd6a0c6dac1b36937f1c7fde51d51d0de7b87f7dfb2d9cdc0cc142c",
			"sync/atomic":          "11ce6b22151ab4e36738fab846491e2bccc453041156333fc7fa36c7b9ec0f45",
		},
	},
	{
		Label: "go1.27.1 plan9/amd64",
		Base:  "go1.27.1",
		Packages: map[string]string{
			"crypto/internal/sysrand":     "e4214f48b69ac66e34cea493b56e72ca208705c652557b20343b4d28961ae62d",
			"crypto/x509":                 "4902029adce78e00e32519204f857c42788a96c2e2cd389e3ea6ac697a02a112",
			"internal/bytealg":            "504de20a9081de8e43cae6594f29ccc3719b1ced26c29ae96569e294efeffa17",
			"internal/filepathlite":       "48fa36289d7a038a0f0ab46de8bd07810c5f1c84587b7d1d60b4fc8df308f31f",
			"internal/fuzz":               "b9759db740b8b718df516bf3c7c3395d3b33be1767e324322f815889326d4d1b",
			"internal/goos":               "372e0c194cf8f197018df3ce8ef923e9ee7c1b2869fea23d86af6c26c947ef0d",
			"internal/poll":               "d0168a997fbc63a5ec7fc80d49c5c0ba5616ceb86c8383b9a3058ca678a3e5d1",
			"internal/sysinfo":            "fb073589be65508e2564fbcf0135ac7e078d3e0a2f34417ef06bd76999295963",
			"mime":                        "60b87b497531786f7a1b1eab3e67d426ac3167723ae8bd8c7c2954babca1cda3",
			"net":                         "a317f96fe4d302f218e0ec412f6351eff3238a1e018d400c2e33493fb863de3f",
			"os":                          "8eedcecf821c7ccb4c5a95f913e2d28fcb659ca3f1b497f83f61f4c4d3f35062",
			"os/exec":                     "48d7ad61db453162deaa352e98e1dbcb5c05f355b5abcb85b84639092e38dec6",
			"os/signal":                   "b8252f7e3e9a60cb015b44621d7d6b67b1e296e583fb12bb7bbbcc179511f6cc",
			"path/filepath":               "01eceadffa489ea0064a5c9301a5378027d2c6ab1b8d5f377ce041e4724e2169",
			"plugin":                      "97933b973cdc749095ef6a6ca7a98b0adb6ceca865351e0b3d4ed66fe15679a6",
			"runtime":                     "121c0756cab907f8cf4aab5e715d3320eafc2ff05edbdd230975dce8b424f42a",
			"runtime/pprof":               "8d1f2524a6d4519a87f302b532234e7931ed532accfad1649f95bf4c7a70c304",
			"runtime/race":                "17f35321561e4de4c1218c53a645899977a52441463b3e9bea41ac9d029f8a56",
			"syscall":                     "8af7a600d937a7013523eb83343db260ff0f659d08b05234f809ecd5af482d23",
			"time":                        "014cec6b524f23cc74d33f11aa539a982ba522e82315991830cc5368d3fc26f4",
			"vendor/golang.org/x/sys/cpu": "1837c2c3644543e68793e1d1cc9546b879007ab8cdc9493452ff4c4a92ecee4e",
		},
	},
	{
		Label: "go1.27.1 cgo0",
		Base:  "go1.27.1",
		Packages: map[string]string{
			"net":    "451424f5348394fb2448077ce5c291aff1d356b9f41c76d953987eece751662b",
			"plugin": "97933b973cdc749095ef6a6ca7a98b0adb6ceca865351e0b3d4ed66fe15679a6",
		},
	},
	// Disabling DWARF 5 selects only the alternate goexperiment constants;
	// it introduces no effectful standard-library body. Code-generation
	// differences remain guarded by the toolchain and build configuration.
	{
		Label: "go1.27.1-X:nodwarf5",
		Base:  "go1.27.1",
		Packages: map[string]string{
			"internal/goexperiment": "1d95601ee0ac49680f29d0f0eceb7de2996604237990ba429be2e72408be7540",
		},
	},
	{
		Label: "go1.27.1-X:nodwarf5 race",
		Base:  "go1.27.1-X:nodwarf5",
		Packages: map[string]string{
			"internal/race":        "8b73d1da46a77b9156aeef8ee93e9bc760417131f993a0bce489e626e32a3920",
			"internal/runtime/sys": "8a4de7b36d428a5ae5fcfd24b979bc6778c60ac017cf1dbbccd938b6455067db",
			"runtime":              "638e64d4290cd7eeab8e91029cc9fbf82911bc0417daac76c73105b825686d9a",
			"runtime/race":         "7a496110fdd6a0c6dac1b36937f1c7fde51d51d0de7b87f7dfb2d9cdc0cc142c",
			"sync/atomic":          "11ce6b22151ab4e36738fab846491e2bccc453041156333fc7fa36c7b9ec0f45",
		},
	},
	{
		Label: "go1.27.1-X:nodwarf5 plan9/amd64",
		Base:  "go1.27.1-X:nodwarf5",
		Packages: map[string]string{
			"crypto/internal/sysrand":     "e4214f48b69ac66e34cea493b56e72ca208705c652557b20343b4d28961ae62d",
			"crypto/x509":                 "4902029adce78e00e32519204f857c42788a96c2e2cd389e3ea6ac697a02a112",
			"internal/bytealg":            "504de20a9081de8e43cae6594f29ccc3719b1ced26c29ae96569e294efeffa17",
			"internal/filepathlite":       "48fa36289d7a038a0f0ab46de8bd07810c5f1c84587b7d1d60b4fc8df308f31f",
			"internal/fuzz":               "b9759db740b8b718df516bf3c7c3395d3b33be1767e324322f815889326d4d1b",
			"internal/goos":               "372e0c194cf8f197018df3ce8ef923e9ee7c1b2869fea23d86af6c26c947ef0d",
			"internal/poll":               "d0168a997fbc63a5ec7fc80d49c5c0ba5616ceb86c8383b9a3058ca678a3e5d1",
			"internal/sysinfo":            "fb073589be65508e2564fbcf0135ac7e078d3e0a2f34417ef06bd76999295963",
			"mime":                        "60b87b497531786f7a1b1eab3e67d426ac3167723ae8bd8c7c2954babca1cda3",
			"net":                         "a317f96fe4d302f218e0ec412f6351eff3238a1e018d400c2e33493fb863de3f",
			"os":                          "8eedcecf821c7ccb4c5a95f913e2d28fcb659ca3f1b497f83f61f4c4d3f35062",
			"os/exec":                     "48d7ad61db453162deaa352e98e1dbcb5c05f355b5abcb85b84639092e38dec6",
			"os/signal":                   "b8252f7e3e9a60cb015b44621d7d6b67b1e296e583fb12bb7bbbcc179511f6cc",
			"path/filepath":               "01eceadffa489ea0064a5c9301a5378027d2c6ab1b8d5f377ce041e4724e2169",
			"plugin":                      "97933b973cdc749095ef6a6ca7a98b0adb6ceca865351e0b3d4ed66fe15679a6",
			"runtime":                     "121c0756cab907f8cf4aab5e715d3320eafc2ff05edbdd230975dce8b424f42a",
			"runtime/pprof":               "8d1f2524a6d4519a87f302b532234e7931ed532accfad1649f95bf4c7a70c304",
			"runtime/race":                "17f35321561e4de4c1218c53a645899977a52441463b3e9bea41ac9d029f8a56",
			"syscall":                     "8af7a600d937a7013523eb83343db260ff0f659d08b05234f809ecd5af482d23",
			"time":                        "014cec6b524f23cc74d33f11aa539a982ba522e82315991830cc5368d3fc26f4",
			"vendor/golang.org/x/sys/cpu": "1837c2c3644543e68793e1d1cc9546b879007ab8cdc9493452ff4c4a92ecee4e",
		},
	},
	{
		Label: "go1.27.1-X:nodwarf5 cgo0",
		Base:  "go1.27.1-X:nodwarf5",
		Packages: map[string]string{
			"net":    "451424f5348394fb2448077ce5c291aff1d356b9f41c76d953987eece751662b",
			"plugin": "97933b973cdc749095ef6a6ca7a98b0adb6ceca865351e0b3d4ed66fe15679a6",
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
			"encoding/json":    "7f095481d1530cc7de83e15a6f237d95ce9da8a4c0747c48ff8264960695ac09",
			"encoding/json/v2": "69ee18e7aa71a127876dacd43c854aefe757ce1b58078ec50d88ef9a67ca76f7",
			"net/http":         "723bd7a3bf1fc94d80d83ac26d2783fb5c2ac10f701c6fd5a26e3ec6afed94a5",
		},
	},
	{
		Label: "go1.27.0 race",
		Base:  "go1.27.0",
		Packages: map[string]string{
			"internal/race":        "8b73d1da46a77b9156aeef8ee93e9bc760417131f993a0bce489e626e32a3920",
			"internal/runtime/sys": "8a4de7b36d428a5ae5fcfd24b979bc6778c60ac017cf1dbbccd938b6455067db",
			"runtime":              "638e64d4290cd7eeab8e91029cc9fbf82911bc0417daac76c73105b825686d9a",
			"runtime/race":         "7a496110fdd6a0c6dac1b36937f1c7fde51d51d0de7b87f7dfb2d9cdc0cc142c",
			"sync/atomic":          "11ce6b22151ab4e36738fab846491e2bccc453041156333fc7fa36c7b9ec0f45",
		},
	},
	{
		Label: "go1.27.0 plan9/amd64",
		Base:  "go1.27.0",
		Packages: map[string]string{
			"crypto/internal/sysrand":     "e4214f48b69ac66e34cea493b56e72ca208705c652557b20343b4d28961ae62d",
			"crypto/x509":                 "4902029adce78e00e32519204f857c42788a96c2e2cd389e3ea6ac697a02a112",
			"internal/bytealg":            "504de20a9081de8e43cae6594f29ccc3719b1ced26c29ae96569e294efeffa17",
			"internal/filepathlite":       "48fa36289d7a038a0f0ab46de8bd07810c5f1c84587b7d1d60b4fc8df308f31f",
			"internal/fuzz":               "b9759db740b8b718df516bf3c7c3395d3b33be1767e324322f815889326d4d1b",
			"internal/goos":               "372e0c194cf8f197018df3ce8ef923e9ee7c1b2869fea23d86af6c26c947ef0d",
			"internal/poll":               "d0168a997fbc63a5ec7fc80d49c5c0ba5616ceb86c8383b9a3058ca678a3e5d1",
			"internal/sysinfo":            "fb073589be65508e2564fbcf0135ac7e078d3e0a2f34417ef06bd76999295963",
			"mime":                        "60b87b497531786f7a1b1eab3e67d426ac3167723ae8bd8c7c2954babca1cda3",
			"net":                         "a317f96fe4d302f218e0ec412f6351eff3238a1e018d400c2e33493fb863de3f",
			"os":                          "8eedcecf821c7ccb4c5a95f913e2d28fcb659ca3f1b497f83f61f4c4d3f35062",
			"os/exec":                     "48d7ad61db453162deaa352e98e1dbcb5c05f355b5abcb85b84639092e38dec6",
			"os/signal":                   "b8252f7e3e9a60cb015b44621d7d6b67b1e296e583fb12bb7bbbcc179511f6cc",
			"path/filepath":               "01eceadffa489ea0064a5c9301a5378027d2c6ab1b8d5f377ce041e4724e2169",
			"plugin":                      "97933b973cdc749095ef6a6ca7a98b0adb6ceca865351e0b3d4ed66fe15679a6",
			"runtime":                     "121c0756cab907f8cf4aab5e715d3320eafc2ff05edbdd230975dce8b424f42a",
			"runtime/pprof":               "8d1f2524a6d4519a87f302b532234e7931ed532accfad1649f95bf4c7a70c304",
			"runtime/race":                "17f35321561e4de4c1218c53a645899977a52441463b3e9bea41ac9d029f8a56",
			"syscall":                     "8af7a600d937a7013523eb83343db260ff0f659d08b05234f809ecd5af482d23",
			"time":                        "014cec6b524f23cc74d33f11aa539a982ba522e82315991830cc5368d3fc26f4",
			"vendor/golang.org/x/sys/cpu": "1837c2c3644543e68793e1d1cc9546b879007ab8cdc9493452ff4c4a92ecee4e",
		},
	},
	{
		Label: "go1.27.0 cgo0",
		Base:  "go1.27.0",
		Packages: map[string]string{
			"net":    "451424f5348394fb2448077ce5c291aff1d356b9f41c76d953987eece751662b",
			"plugin": "97933b973cdc749095ef6a6ca7a98b0adb6ceca865351e0b3d4ed66fe15679a6",
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
			"compress/flate":                "7eec49c7a59406790dfeaff8ce48a9cd82da7705f01faa62fd84bdd499a4680c",
			"crypto/internal/fips140/mlkem": "756e633fe7707bc5f4c3469f10647a15f81c1508e4a931b2ebbef3e94ec79c3a",
			"crypto/tls":                    "9dfdfdbd4fac3d54521890c32cf846bf678e9c381d0778e039144840454a85a9",
			"encoding/json":                 "ee42752900db78e6235e23be50dbb856a023b97e2f2ed0f97c131c846b91fabc",
			"encoding/json/internal":        "a1d3d12a048459c2cdce2331af5403190d004152b356afbbe556a12e86c51eef",
			"encoding/json/v2":              "1ff5d9f9603d3b9e232b6f367ec3dfee4a5343eaad5da0ad014b93c5607ca7be",
			"html/template":                 "11c33fad5878dfa9ba97ce4e2b0da2b2876db68be8ab55af5b6040640561d6bf",
			"internal/godebugs":             "583aa7271393e9e0e432083350695d0e1ff39e570c5dec1681eb0843822adf9b",
			"mime/multipart":                "75e87bb9a444a090e161aab9bb9c531a46ad450f73de86d82bae37ff47418293",
			"net/http":                      "9123cf6e9b7989c458e82a262dd9105e7c972d21a05fe049f3a1c98bd219ed29",
			"net/http/internal/http2":       "93d41ada54e4a10d19632b955a3d2bfb249ef3935d3b831e7649b4ff8936799e",
			"net/textproto":                 "19b0da7f73e5de734e3c4c5526e74344ebf3e41459e8c23e1ee0084703323363",
			"os":                            "9b8b62235756fc8d7a7c8b23b69372e61304949a628a556486fb8186d3a5a882",
			"runtime":                       "40277defafcb524bc6ec70ed6a64c4c78689144ed04140011e913474cbca9b34",
			"testing":                       "a946e6aca65f2d0121e213ab266e1500f0bf323bf43b325b50a83c481abf142e",
		},
	},
	{
		Label: "go1.27.2 race",
		Base:  "go1.27.2",
		Packages: map[string]string{
			"internal/race":        "8b73d1da46a77b9156aeef8ee93e9bc760417131f993a0bce489e626e32a3920",
			"internal/runtime/sys": "8a4de7b36d428a5ae5fcfd24b979bc6778c60ac017cf1dbbccd938b6455067db",
			"runtime":              "2a6bd25db532bc11f54eec211596e64e59d1274c0d835810befbf10e289117d2",
			"runtime/race":         "7a496110fdd6a0c6dac1b36937f1c7fde51d51d0de7b87f7dfb2d9cdc0cc142c",
			"sync/atomic":          "11ce6b22151ab4e36738fab846491e2bccc453041156333fc7fa36c7b9ec0f45",
		},
	},
	{
		Label: "go1.27.2 plan9/amd64",
		Base:  "go1.27.1 plan9/amd64",
		Packages: map[string]string{
			"compress/flate":                "7eec49c7a59406790dfeaff8ce48a9cd82da7705f01faa62fd84bdd499a4680c",
			"crypto/internal/fips140/mlkem": "756e633fe7707bc5f4c3469f10647a15f81c1508e4a931b2ebbef3e94ec79c3a",
			"crypto/tls":                    "9dfdfdbd4fac3d54521890c32cf846bf678e9c381d0778e039144840454a85a9",
			"encoding/json":                 "ee42752900db78e6235e23be50dbb856a023b97e2f2ed0f97c131c846b91fabc",
			"encoding/json/internal":        "a1d3d12a048459c2cdce2331af5403190d004152b356afbbe556a12e86c51eef",
			"encoding/json/v2":              "1ff5d9f9603d3b9e232b6f367ec3dfee4a5343eaad5da0ad014b93c5607ca7be",
			"html/template":                 "11c33fad5878dfa9ba97ce4e2b0da2b2876db68be8ab55af5b6040640561d6bf",
			"internal/godebugs":             "583aa7271393e9e0e432083350695d0e1ff39e570c5dec1681eb0843822adf9b",
			"mime/multipart":                "75e87bb9a444a090e161aab9bb9c531a46ad450f73de86d82bae37ff47418293",
			"net/http":                      "9123cf6e9b7989c458e82a262dd9105e7c972d21a05fe049f3a1c98bd219ed29",
			"net/http/internal/http2":       "93d41ada54e4a10d19632b955a3d2bfb249ef3935d3b831e7649b4ff8936799e",
			"net/textproto":                 "19b0da7f73e5de734e3c4c5526e74344ebf3e41459e8c23e1ee0084703323363",
			"runtime":                       "04b6b871782b9b9bac67d17033ba0ee7d09b133d7646f421bda655ea21af92b2",
			"testing":                       "a946e6aca65f2d0121e213ab266e1500f0bf323bf43b325b50a83c481abf142e",
		},
	},
	{
		Label: "go1.27.2 cgo0",
		Base:  "go1.27.2",
		Packages: map[string]string{
			"net":    "451424f5348394fb2448077ce5c291aff1d356b9f41c76d953987eece751662b",
			"plugin": "97933b973cdc749095ef6a6ca7a98b0adb6ceca865351e0b3d4ed66fe15679a6",
		},
	},
	// The repaired godst harness returns every test-log write failure to
	// the buffered logger, whose flush fails the process. A dropped block
	// of whole records is otherwise indistinguishable from a quiet test;
	// a completion receipt cannot recover those missing observations.
	// The free-function printer/stat helpers preserve observation routing;
	// finalizer scratch remains private to each driver.
	//
	// The dst admissions rest on the enabled branches, not just the tagged
	// files. Simulated filesystem operations may return before stock
	// logging sites, but the filesystem is host-isolated, simulation is
	// process-global for the run, and simulated changes never move the host
	// cwd. Logging a simulated path can over-pin a host path, not omit a
	// host read. The syscall environment is per-process copy-on-write:
	// os.Getenv logs before delegation and unmodified keys retain their
	// host values. Raw intercepted syscalls remain outside pure admissions.
	//
	// Time's location and zoneinfo fences affect operations excluded from
	// the fixed-argument admissions; the virtual clock is not admitted.
	// Internal synchronization hooks under dst, and the additional sync
	// hooks under dst && race, change scheduling and starvation decisions,
	// not the audited methods' values or memo semantics. The os/signal
	// fence panics inside an active bubble; none of its operations is a
	// pure admission. Deterministic sysrand remains entropy-classed, map
	// iteration grants no admission, and runtime/network hooks remain
	// effectful.
	{
		Label: "go1.27.2-dst.15",
		Base:  "go1.27.1-dst.13",
		Packages: map[string]string{
			"compress/flate":                "7eec49c7a59406790dfeaff8ce48a9cd82da7705f01faa62fd84bdd499a4680c",
			"crypto/internal/fips140/mlkem": "756e633fe7707bc5f4c3469f10647a15f81c1508e4a931b2ebbef3e94ec79c3a",
			"crypto/tls":                    "9dfdfdbd4fac3d54521890c32cf846bf678e9c381d0778e039144840454a85a9",
			"encoding/json":                 "ee42752900db78e6235e23be50dbb856a023b97e2f2ed0f97c131c846b91fabc",
			"encoding/json/internal":        "a1d3d12a048459c2cdce2331af5403190d004152b356afbbe556a12e86c51eef",
			"encoding/json/v2":              "1ff5d9f9603d3b9e232b6f367ec3dfee4a5343eaad5da0ad014b93c5607ca7be",
			"html/template":                 "11c33fad5878dfa9ba97ce4e2b0da2b2876db68be8ab55af5b6040640561d6bf",
			"internal/godebugs":             "583aa7271393e9e0e432083350695d0e1ff39e570c5dec1681eb0843822adf9b",
			"mime/multipart":                "75e87bb9a444a090e161aab9bb9c531a46ad450f73de86d82bae37ff47418293",
			"net/http":                      "9123cf6e9b7989c458e82a262dd9105e7c972d21a05fe049f3a1c98bd219ed29",
			"net/http/internal/http2":       "93d41ada54e4a10d19632b955a3d2bfb249ef3935d3b831e7649b4ff8936799e",
			"net/textproto":                 "19b0da7f73e5de734e3c4c5526e74344ebf3e41459e8c23e1ee0084703323363",
			"os":                            "84b4293681b1ccf9a6ee712aa02e08be108fbc4d7de485f9af5043706f6ae2bf",
			"runtime":                       "722cad6ef5d66e649613a17c446207d21ef10ded1b558a290e503786cdcb77be",
			"testing":                       "5782bb6a792f863294779e8451783acaf03a2645cf83c8ada254b89500e8971b",
		},
	},
	{
		Label: "go1.27.2-dst.15 race",
		Base:  "go1.27.2-dst.15",
		Packages: map[string]string{
			"internal/race":        "8b73d1da46a77b9156aeef8ee93e9bc760417131f993a0bce489e626e32a3920",
			"internal/runtime/sys": "8a4de7b36d428a5ae5fcfd24b979bc6778c60ac017cf1dbbccd938b6455067db",
			"runtime":              "56dce067e756491f19aa6f63e3b4dc7051c88312c79ed467d562e525b3986139",
			"runtime/race":         "7a496110fdd6a0c6dac1b36937f1c7fde51d51d0de7b87f7dfb2d9cdc0cc142c",
			"sync/atomic":          "11ce6b22151ab4e36738fab846491e2bccc453041156333fc7fa36c7b9ec0f45",
		},
	},
	{
		Label: "go1.27.2-dst.15 plan9/amd64",
		Base:  "go1.27.1-dst.13 plan9/amd64",
		Packages: map[string]string{
			"compress/flate":                "7eec49c7a59406790dfeaff8ce48a9cd82da7705f01faa62fd84bdd499a4680c",
			"crypto/internal/fips140/mlkem": "756e633fe7707bc5f4c3469f10647a15f81c1508e4a931b2ebbef3e94ec79c3a",
			"crypto/tls":                    "9dfdfdbd4fac3d54521890c32cf846bf678e9c381d0778e039144840454a85a9",
			"encoding/json":                 "ee42752900db78e6235e23be50dbb856a023b97e2f2ed0f97c131c846b91fabc",
			"encoding/json/internal":        "a1d3d12a048459c2cdce2331af5403190d004152b356afbbe556a12e86c51eef",
			"encoding/json/v2":              "1ff5d9f9603d3b9e232b6f367ec3dfee4a5343eaad5da0ad014b93c5607ca7be",
			"html/template":                 "11c33fad5878dfa9ba97ce4e2b0da2b2876db68be8ab55af5b6040640561d6bf",
			"internal/godebugs":             "583aa7271393e9e0e432083350695d0e1ff39e570c5dec1681eb0843822adf9b",
			"mime/multipart":                "75e87bb9a444a090e161aab9bb9c531a46ad450f73de86d82bae37ff47418293",
			"net/http":                      "9123cf6e9b7989c458e82a262dd9105e7c972d21a05fe049f3a1c98bd219ed29",
			"net/http/internal/http2":       "93d41ada54e4a10d19632b955a3d2bfb249ef3935d3b831e7649b4ff8936799e",
			"net/textproto":                 "19b0da7f73e5de734e3c4c5526e74344ebf3e41459e8c23e1ee0084703323363",
			"os":                            "c66271f180d9b3082bf4087dd03f49346fbfb14b3487328ae0fe95aacb9f02b3",
			"runtime":                       "30a09d92a59d6d9753fcdbbdc73a37e2f7c357279ec256d5cea1b30ec5478206",
			"testing":                       "5782bb6a792f863294779e8451783acaf03a2645cf83c8ada254b89500e8971b",
		},
	},
	{
		Label: "go1.27.2-dst.15 cgo0",
		Base:  "go1.27.2-dst.15",
		Packages: map[string]string{
			"net":    "a18b2c37538467a94cda1019585467671e2e1136c3df22f41dff58a072453956",
			"plugin": "97933b973cdc749095ef6a6ca7a98b0adb6ceca865351e0b3d4ed66fe15679a6",
		},
	},
	{
		Label: "go1.27.2-dst.15 dst",
		Base:  "go1.27.2-dst.15",
		Packages: map[string]string{
			"crypto/internal/sysrand": "94ea8cb7e698c5779ff5339eb33b50db432e9f6f59090d36a51ffd72501f810b",
			"internal/runtime/maps":   "28e055ebb3f53fdbeb4eedae803c708cb902ab61ecd054924224627c12f94709",
			"internal/sync":           "8981466505cbd5b87e69d4ab2600356fdc0c499cae8581607705deee5cf7a757",
			"net":                     "4ff1194151242fbb1127b6f6ccd21d82fed79d81e01cc3ccee921608e015d11a",
			"os":                      "3e8d308cc6641b5c770ab04d0a14dd7953bfa112f5d15305885ce4ee815363c6",
			"os/signal":               "bb18288e7ae2dc52a6a378d5e5c780eeab363388267a79d151961046c15fee40",
			"runtime":                 "bd635a32ee3369cf568a5e41b00985420fca8f10a576f18c32038ef6b2d9f4a8",
			"syscall":                 "6b429bf2dd58364899de8b1c08558a849e6bdf55528a381f460a9cea36463587",
			"testing":                 "8ffab5a28f8db45b2e64366752fd23580d3cfa19db1140bbe981789faa2f2209",
			"time":                    "2ddf4da5cb9e7d43d10a23bb65ec39f41847ce4b537a43ccc2a52da6eb474203",
		},
	},
	{
		Label: "go1.27.2-dst.15 dst race",
		Base:  "go1.27.2-dst.15 dst",
		Packages: map[string]string{
			"internal/race":        "8b73d1da46a77b9156aeef8ee93e9bc760417131f993a0bce489e626e32a3920",
			"internal/runtime/sys": "8a4de7b36d428a5ae5fcfd24b979bc6778c60ac017cf1dbbccd938b6455067db",
			"internal/sync":        "44c39856957e5e832fdd2d6ab0d3d5800799e28fb4f43053a705d59560bc861c",
			"runtime":              "a38decf61888f12d89b890c88a4baaa8ed7262adc81afbb32fc7ba53a1d4c2ba",
			"runtime/race":         "7a496110fdd6a0c6dac1b36937f1c7fde51d51d0de7b87f7dfb2d9cdc0cc142c",
			"sync":                 "7b95f66f388096b0d8281b2a03cc8a454566bcb6816d60115d2ae6d1ea83484b",
			"sync/atomic":          "11ce6b22151ab4e36738fab846491e2bccc453041156333fc7fa36c7b9ec0f45",
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
	d.Policy = admissionPolicy()
	if listErr == nil {
		for _, root := range auditedSurfaceTables() {
			first, _, _ := strings.Cut(root, "/")
			if strings.Contains(first, ".") {
				continue
			} // module-version audits
			if _, ok := d.inventory[root]; !ok {
				listErr = fmt.Errorf("required audited standard package %s was not inventoried", root)
				d.Content = ""
				break
			}
		}
	}
	if ctx.Err() != nil {
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
