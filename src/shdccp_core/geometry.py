"""Exact integer spatial invariants and an intentionally simple cubic address."""
import math

def quadrance(a,b):
    if len(a)!=3 or len(b)!=3 or any(not isinstance(c,int) for c in (*a,*b)):
        raise ValueError('expected two length-3 integer coordinate vectors')
    return sum((x-y)**2 for x,y in zip(a,b))

def triple_quad(p1,p2,p3):
    """16*area^2 = 4 Q12*Q23 - (Q12+Q23-Q13)^2.
    Exact nonnegative integer for any Euclidean 3D triangle.
    This invariant alone cannot register unknown coordinate frames.
    """
    a=quadrance(p1,p2); b=quadrance(p2,p3); c=quadrance(p1,p3)
    area16=4*a*b-(a+b-c)**2
    if area16<0: raise AssertionError('invalid Euclidean squared distances')
    return {'q12':a,'q23':b,'q13':c,'area16':area16,'collinear':area16==0}

def cubic_address(p,side=4):
    if not isinstance(side,int) or side<=0: raise ValueError('positive integer voxel side required')
    if len(p)!=3 or any(not isinstance(v,int) for v in p): raise ValueError('integer point required')
    return tuple(v//side for v in p)
