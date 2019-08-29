import math

#linear algebra constant 
OMEGA = 2
#Maximal bit-depth of a Quantum computation 
MAXDEPTH = 64

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
def estimateGroebnerBasisComputation(m,n,r):
    if (m,n) not in GBDict :
        Dreg = estimateDreg(m,n)
        GBDict[(m,n)] = (OMEGA * log2(binom(Dreg+n,n)),Dreg)
    return GBDict[(m,n)]

#estimates the bit complexity of a direct attack 
def directAttack(r,m,v):
	#Thomae et al.
	m = m - v//m 

	k = 0
	best, bestdeg = estimateGroebnerBasisComputation(m,m,r)
	bestk = 0
	while k<m-3:
		k += 1
		cost, deg = estimateGroebnerBasisComputation(m,m-k,r)
		cost += r*k 
		if cost < best:
			best, bestdeg, bestk = cost , deg , k
	return best,bestdeg,bestk

def BinarySystem(m):
	return min(m,0.8*m)

def UOVAttack(r,m,v):
	return v-m-1+4*log2(v+m)

def QuantumUOVAttack(r,m,v):
	return max((v-m-1)/2+4*log2(v+m) , UOVAttack(r,m,v) - MAXDEPTH )

def UOVReconciliationAttack(r,m,v):
	return BinarySystem(v);

def QuantumUOVReconciliationAttack(r,m,v):
	return max(0.5 *v , v - MAXDEPTH )

def HashCollisionAttack(r,m,v):
	return min(r*m/2 , 512)

def getD(r,m,v):
	d = math.ceil((r*m+0.0)/(m+v))
	while (r % d) != 0:
		d += 1
	return d

def SubfieldDifferentialAttack(r,m,v):
	d = getD(r,m,v)
	s = r/d
	return directAttack(d,m,v-(s-1)*m)

def SubspaceDifferentialAttack(r,m,v):
	d = math.ceil((r*m+0.0)/(m+v))
	equations = (2*d-1)*m
	variables = d*(m+v)-(r-2*d+1)*m
	#equations = equations + 1 - math.floor(variables/equations)
	return equations,variables , max( 0.5*equations , equations - MAXDEPTH);

def SummarizeAttacks(r,m,v,doPrint = True):
    d,dreg,k = directAttack(r,m,v)
    UOV      = UOVAttack(r,m,v)
    qUOV     = QuantumUOVAttack(r,m,v)
    Rec      = UOVReconciliationAttack(r,m,v)
    qRec     = QuantumUOVReconciliationAttack(r,m,v)
    hc       = HashCollisionAttack(r,m,v)
    sd,_,_   = SubfieldDifferentialAttack(r,m,v)
    ssd,ssdvar, qssd = SubspaceDifferentialAttack(r,m,v)
    total = min(d,UOV,Rec,hc)
    totalq= min(qUOV , qRec)

    if doPrint : 
        print ("parameters r = ",r," m = ",m," v = ",v)
        print ("attack                        | bit complexity ")
        print ("-----------------------------------------------")
        print ("direct attack                 | ",d," (d_reg = ",dreg," k=",k,")")
        print ("UOV attack                    | ",UOV)
        print ("quantum UOV attack            | ",qUOV)
        print ("Reconciliation attack         | ",Rec)
        print ("quantum reconciliation attack | ",qRec)
        print ("hash collsion attack          | ",hc)
        print ("subfield differential attack  | ",sd," (d=",getD(r,m,v),")")
        print ("subspace differential attack  | ",ssd,"eqns and", ssdvar, "vars (d=",math.ceil((r*m+0.0)/(m+v)),")")
        print ("quantum subspace diff. attack | ",qssd,"eqns and", ssdvar, "vars (d=",math.ceil((r*m+0.0)/(m+v)),")")
        print ("-----------------------------------------------")
        print ("best classical attack         | ",total)
        print ("best quantum attack           | ",totalq)
        print ("")
        print ("public key takes ",5+math.ceil(m*m*(m+1)/16)," bytes")
        print ("signature takes ",(r*(m+v)/8)+16," bytes")

    return total,totalq

def chooseParams(r,l,lq = 0):
    if lq == 0:
	    lq = l
    m = 5
    v = 5
    while min(directAttack(r,m,v)[0],SubfieldDifferentialAttack(r,m,v)[0]) < l:
        m += 1
        while min(directAttack(r,m,v)[0],SubfieldDifferentialAttack(r,m,v)[0]) >= l :
            classical , quantum = SummarizeAttacks(r,m,v, False)
            if classical > l and quantum > lq:
                break
            v += 1 

    SummarizeAttacks(r,m,v)

#levels 2,4,5
#small key
chooseParams(47,143,170-MAXDEPTH)
chooseParams(61,207,233-MAXDEPTH)
chooseParams(79,272,298-MAXDEPTH)
#small signature
chooseParams(7,143,170-MAXDEPTH)
chooseParams(7,207,233-MAXDEPTH)
chooseParams(7,272 ,298-MAXDEPTH)


