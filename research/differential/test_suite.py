"""Checks for statistical budgeting and search plumbing, including planted failures."""
import argparse
import math
import unittest
import suite

class ConstantHash:
    def hashes(self, algo, bits, seed, data, length, count):
        return bytes((bits//8)*count)

class Tests(unittest.TestCase):
    def test_discovery_budget(self):
        for p in (.5,.01,1e-6):
            b=suite.bounds(1000,123,256,.01,p)
            n=b['samples_per_delta_for_discovery']
            self.assertLessEqual(math.log(123/p)+n*math.log1p(-p),math.log(.01))
            self.assertGreater(math.log(123/p)+(n-1)*math.log1p(-p),math.log(.01))

    def test_zero_event_bound(self):
        b=suite.bounds(100,7,64,.01,.1)
        self.assertAlmostEqual((1-b['zero_collision_upper'])**100,.01/7)

    def test_planted_collision_and_bias(self):
        args=argparse.Namespace(lengths=[1],all_bits=False,masks=None,algorithm='rainbow',bits=64,
            alpha=.01,samples=512,replay_seed=1,batch=127,hash_seed=0,p_min=.1)
        result=suite.scan(ConstantHash(),args)
        for row in result['records']:
            self.assertEqual(row['collisions'],512)
            self.assertEqual(row['most_frequent_count'],512)
            self.assertEqual(row['max_bit_bias'],.5)
            self.assertTrue(row['projection_alerts'])
            a,b=row['collision_witness']
            self.assertNotEqual(a,b)
            self.assertEqual(int(a,16)^int(b,16),int(row['input_xor_hex_little_endian'],16))

    def test_exhaustive_planted_collision(self):
        args=argparse.Namespace(domain_bits=4,algorithm='rainstorm',bits=128,hash_seed=0)
        result=suite.exhaustive(ConstantHash(),args)
        self.assertEqual(len(result['rows']),15)
        self.assertTrue(all(r['collision_count']==16 and r['max_probability']==1 for r in result['rows']))

if __name__=='__main__': unittest.main()
