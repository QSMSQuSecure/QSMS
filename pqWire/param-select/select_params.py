#/*---------------------------------------------------------------------
#This file has been adapted from the implementation
#(available at, Public Domain https://github.com/pq-crystals/kyber)
#of "CRYSTALS - Kyber: a CCA-secure module-lattice-based KEM"
#by : Joppe Bos, Leo Ducas, Eike Kiltz, Tancrede Lepoint,
#Vadim Lyubashevsky, John M. Schanck, Peter Schwabe & Damien stehle
#----------------------------------------------------------------------*/ 

import numpy as np
import matplotlib.pyplot as plt
import pqsec
from math import sqrt, exp, log, floor
from proba_util import *



def error_distribution(coins, q, p, t, n):
    """ construct the final error distribution in our encryption scheme
    :param ps: parameter set (ParameterSet), s, q, p, t, n, k, s
    """
    s = build_centered_binomial_law(coins/2)    # pdf secret
    e = build_mod_switching_error_law(q, p)    	# pdf error

    se = law_product(s, e)
    se2 = iter_law_convolution(se, n)
    se2 = convolution_remove_dependency(se2, se2, q, p)

    e2 = build_mod_switching_error_law(q, 2*t)
    
    C=law_convolution(se2, e2)

    return C

def error_probability(coins,q,p,t,n):
    F = error_distribution(coins, q, p, t, n)
    prob = tail_probability(F, q/4.)
    if prob!=0:
    	prob = log(256*prob,2)  
    return(prob)

def search_params(coins_secret,q,k,n,security,maxerror):
    std_secret = sqrt(coins_secret/4.)
    logq=log(q,2)

    # loop over all p values that are a power of 2 (from 10, others are too low, by experiment)
    for logp in range(8,int(floor(log(q,2)))):
        p=2**logp

        ### loop over all reconciliation values
        for logt in range(2,logp-1):
            t=2**logt
            zeta=min(q/p,p/(2*t))

            ### check security
            _, _, c1b = pqsec.optimize_attack_LWR(q, q/zeta, k*n, (k+1)*n, std_secret, cost_attack=pqsec.primal_cost_LWR, cost_svp=pqsec.svp_quantum)
            _, _, c2b = pqsec.optimize_attack_LWR(q, q/zeta, k*n, (k+1)*n, std_secret, cost_attack=pqsec.dual_cost_LWR, cost_svp=pqsec.svp_quantum)
            
            # if the security if not enough, b is too high and we do not have too look any further
            if c1b<security or c2b<security:
                break

            ### get an upper bound on the failure rate
            # if the error is too big, we need to increase b
            #error_old=error_probability(coins_secret,q,p,t,k*n)
            error=error_probability(coins_secret,q,p,t,k*n)
            if error>maxerror:
                continue

            ######################################################
            ### We have found good parameters, give a printout ###

            ### bandwidth calculation
            # size of b in bytes
            BWb=logp*k*n/8
            # size of c in bytes
            BWc = n*(logt+1)/8

            BWs = ceil(log(coins_secret,2))*k*n/8
            BWsfull = logq*k*n/8

            print('-- parameters --')
            print('q: ',log(q,2),'p: ',logp,'t: ',logt, 'l: ', k, 'n: ', n, 'coins: ', coins_secret)
            
            print('-- bandwidth --')
            print('bandwidth b', BWb, 'bandwidth c', BWc, 'bandwidth total', 2*BWb + BWc + 256/8)
            print('KEM')
            #pk: b, seedA; sk: b, s, (z,seedA,H(pk))
            print('pk: ',BWb + 32, 'sk: ', 3*32+BWb+BWs, 3*32+BWb+BWsfull, 'send: ', BWb+BWc)
            print('PKE')
            print('pk: ',BWb + 32, 'sk: ', BWs, BWsfull, 'send: ', BWb+BWc)

            print('-- correctness --')
            print('failure probability: ', error)

            print('-- security --')
            print('> This is an estimate of the security, more exact and up to date security estimates can be found at https://estimate-all-the-lwe-ntru-schemes.github.io/docs/')
            for i in [pqsec.svp_classical, pqsec.svp_quantum, pqsec.svp_plausible]:
                _, _, c1p = pqsec.optimize_attack_LWR(q, q/zeta, k*n, (k+1)*n, std_secret, cost_attack=pqsec.primal_cost_LWR, cost_svp=i)
                _, _, c2p = pqsec.optimize_attack_LWR(q, q/zeta, k*n, (k+1)*n, std_secret, cost_attack=pqsec.dual_cost_LWR, cost_svp=i)
                print(i, c1p, c2p)

            # succes, we found a b that is secure, and don't need to increase b 
            break


def main():
    # search_params(binomial coins, q, k, n, log2(security), log2(failure probability)
    # script looks for optimal p and t
    # parameter for binomial distribution in Kyber is (binomial coins)/2
    print('-saber-')
    search_params(8,2**13,3,256,128,-25)
    print('\n\n')
    #print('-lightsaber-')
    #search_params(10,2**13,2,256,100,-100)
    #print('\n\n')
    #print('-firesaber-')
    #search_params(6,2**13,4,256,160,-160)




if __name__ == '__main__':
    main()
