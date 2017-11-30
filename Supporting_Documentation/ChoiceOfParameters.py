import math

#linear algebra constant 
OMEGA = 2
#Maximal bit-depth of a Quantum computation 
MAXDEPTH = 64
#Extra security margin
MARGIN = 1.1

def binom(n,k):
	if k<0 or k>n:
		return 0
	return (math.factorial(n)//math.factorial(k))//math.factorial(n-k)

def log2(a):
	return math.log(a)/math.log(2)

#calculates the degree of regularity of an overdetermined semi-regular quadratic system of m equations in n variables 
def estimateDreg(m,n):
    if m<n:
        raise ValueError("underdetermined system")

    Dreg = 0
    nextCoef = 1;

    while nextCoef>0:
        Dreg += 1
        nextCoef = 0
        for i in range(Dreg+1):
            if i%2 == 0 :
                nextCoef += binom(m-n,i)*binom(m,Dreg-i)
            else:
                nextCoef -= binom(m-n,i)*binom(m,Dreg-i)
    return Dreg

GBDict = {}

#estimates the bit complexity of a groebner basis computation
def estimateGroebnerBasisComputation(m,n):
    if (m,n) not in GBDict :
        Dreg = estimateDreg(m,n)
        GBDict[(m,n)] = OMEGA * log2(binom(Dreg+n,n))
    return GBDict[(m,n)]

#estimates the bit complexity of a direct attack 
def directAttack(r,m,v):
	#Thomae et al.
	m = m - v//m 

	k = 0
	best = estimateGroebnerBasisComputation(m,m)

	while True:
		k += 1
		cost = r*k + estimateGroebnerBasisComputation(m,m-k)
		if cost < best:
			best = cost
		else:
			break;
	return best

def UOVAttack(r,m,v):
	return v-m-1+4*log2(v+m)

def QuantumUOVAttack(r,m,v):
	return max((v-m-1)/2+4*log2(v+m) , UOVAttack(r,m,v) - MAXDEPTH )

def UOVReconciliationAttack(r,m,v):
	return 0.75 * v

def QuantumUOVReconciliationAttack(r,m,v):
	return max(0.5 *v , v - MAXDEPTH )

def HashCollisionAttack(r,m,v):
	return min(r*m/2 , 512)

def SummarizeAttacks(r,m,v,doPrint = True):
	d     = directAttack(r,m,v)
	UOV   = UOVAttack(r,m,v)
	qUOV  = QuantumUOVAttack(r,m,v)
	Rec   = UOVReconciliationAttack(r,m,v)
	qRec  = QuantumUOVReconciliationAttack(r,m,v)
	hc    = HashCollisionAttack(r,m,v)
	total = min(d,UOV,Rec,hc)
	totalq= min(qUOV , qRec)

	if doPrint : 
	    print "parameters r = ",r," m = ",m," v = ",v 
	    print "attack                        | bit complexity "
	    print "-----------------------------------------------"
	    print "direct attack                 | ",d
	    print "UOV attack                    | ",UOV
	    print "quantum UOV attack            | ",qUOV
	    print "Reconciliation attack         | ",Rec
	    print "quantum reconciliation attack | ",qRec
	    print "hash collsion attack          | ",hc
	    print "-----------------------------------------------"
	    print "best classical attack         | ",total
	    print "best quantum attack           | ",totalq
	    print ""
	    print "public key takes ",5+math.ceil(m*m*(m+1)/16)," bytes"
	    print "signature takes ",r*(m+v)/8," bytes"

	return total,totalq

def chooseParams(r,l,lq = 0):
    if lq == 0:
	    lq = l
    m = 5
    v = 5
    while directAttack(r,m,v) < l:
        m += 1
        while directAttack(r,m,v) >= l :
            classical , quantum = SummarizeAttacks(r,m,v, False)
            if classical > l and quantum > lq:
                break
            v += 1 

    SummarizeAttacks(r,m,v)

chooseParams(48,146*MARGIN)
chooseParams(64,210*MARGIN)
chooseParams(80,272*MARGIN,(298-MAXDEPTH)*MARGIN)

chooseParams(8,146*MARGIN)
chooseParams(8,210*MARGIN)
chooseParams(8,272*MARGIN ,(298-MAXDEPTH)*MARGIN)
