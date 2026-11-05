package lin

// byteFreq is how often each byte occurs in source code, in parts per million. It was counted over the
// text files of the perf corpus (253,685,166 bytes of public Go, JavaScript, JSON and TypeScript), and it
// has one use: choosing how to look for the start of a match. A byte that is rare in code is a cheap
// place to start looking, a byte that is common is not. Another corpus would move the numbers a little and
// never the choice by much, and a wrong choice costs time, never a result.
var byteFreq = [256]uint32{
	0, 0, 0, 0, 0, 0, 0, 0, 0, 21884, 26188, 0, 0, 4, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	173227, 987, 13405, 651, 577, 484, 1158, 1326, 9746, 9731, 2325, 1123, 20543, 2813, 13698, 9468,
	16531, 7837, 6071, 4205, 4336, 2917, 3968, 2474, 3547, 2501, 9493, 3606, 1062, 7532, 1192, 428,
	225, 18875, 2899, 8808, 3465, 5457, 2696, 1740, 1208, 4673, 395, 1073, 2821, 3074, 2902, 3828,
	3588, 961, 4141, 5720, 4667, 1702, 2930, 1167, 1768, 860, 589, 2207, 3918, 2201, 92, 4660,
	1371, 33098, 7464, 19701, 17255, 61175, 14189, 9898, 11638, 34234, 1216, 4103, 20725, 11924, 35400, 31234,
	15387, 1067, 36028, 31836, 46102, 17526, 6247, 4268, 11167, 7243, 1189, 5851, 1149, 5840, 29, 0,
	55, 21, 30, 22, 15, 19, 17, 18, 23, 15, 16, 13, 17, 24, 12, 33,
	13, 17, 14, 13, 21, 21, 14, 15, 17, 34, 14, 12, 17, 16, 19, 56,
	13, 14, 11, 13, 21, 15, 14, 19, 15, 17, 14, 12, 13, 13, 18, 15,
	19, 16, 15, 14, 13, 15, 11, 88, 32, 23, 16, 18, 21, 22, 20, 18,
	0, 0, 95, 21, 4, 3, 0, 0, 0, 1, 1, 0, 3, 1, 12, 3,
	35, 15, 0, 0, 0, 1, 1, 9, 22, 20, 1, 5, 0, 0, 0, 0,
	30, 21, 85, 15, 10, 51, 52, 44, 42, 34, 3, 8, 10, 4, 5, 13,
	52, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
}

// freqOf is the probability that a byte of source code is b, with a floor so that a byte the corpus never
// held does not look free.
func freqOf(b byte) float64 { return float64(max(byteFreq[b], 1)) / 1e6 }
