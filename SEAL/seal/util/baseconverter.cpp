#include <stdexcept>
#include "seal/util/mempool.h"
#include "seal/util/uintcore.h"
#include "seal/memorypoolhandle.h"
#include "seal/smallmodulus.h"
#include "seal/util/baseconverter.h"
#include "seal/util/uintarith.h"
#include "seal/util/uintarithsmallmod.h"
#include "seal/util/uintarithmod.h"
#include "seal/defaultparams.h"
#include "seal/util/smallntt.h"
#include "seal/util/globals.h"

using namespace std;

namespace seal
{
    namespace util
    {
        BaseConverter::BaseConverter(const BaseConverter &copy) : pool_(copy.pool_), generated_(copy.generated_),
            m_tilde_(copy.m_tilde_), m_sk_(copy.m_sk_), coeff_base_mod_count_(copy.coeff_base_mod_count_), aux_base_mod_count_(copy.aux_base_mod_count_),
            coeff_base_array_(copy.coeff_base_array_), aux_base_array_(copy.aux_base_array_), inv_aux_products_mod_msk_(copy.inv_aux_products_mod_msk_),
            bsk_base_mod_count_(copy.bsk_base_mod_count_), inv_coeff_products_mod_mtilde_(copy.inv_coeff_products_mod_mtilde_), coeff_count_(copy.coeff_count_),
            bsk_base_array_(copy.bsk_base_array_), plain_gamma_array_(copy.plain_gamma_array_), gamma_(copy.gamma_), inv_gamma_mod_plain_(copy.inv_gamma_mod_plain_),
            plain_gamma_count_(copy.plain_gamma_count_), bsk_small_ntt_table_(copy.bsk_small_ntt_table_)
        {
            if (generated_)
            {
                mtilde_inv_coeff_base_products_mod_coeff_array_ = copy.mtilde_inv_coeff_base_products_mod_coeff_array_;
                inv_aux_base_products_mod_aux_array_ = copy.inv_aux_base_products_mod_aux_array_;
                inv_coeff_base_products_mod_coeff_array_ = copy.inv_coeff_base_products_mod_coeff_array_;
                coeff_base_products_mod_mtilde_array_ = copy.coeff_base_products_mod_mtilde_array_;
                inv_coeff_products_all_mod_aux_bsk_array_ = copy.inv_coeff_products_all_mod_aux_bsk_array_;
                coeff_base_products_mod_aux_bsk_array_ = copy.coeff_base_products_mod_aux_bsk_array_;
                aux_base_products_mod_coeff_array_ = copy.aux_base_products_mod_coeff_array_;
                aux_base_products_mod_msk_array_ = copy.aux_base_products_mod_msk_array_;
                aux_products_all_mod_coeff_array_ = copy.aux_products_all_mod_coeff_array_;
                coeff_products_all_mod_bsk_array_ = copy.coeff_products_all_mod_bsk_array_;
                inv_mtilde_mod_bsk_array_ = copy.inv_mtilde_mod_bsk_array_;
                coeff_products_mod_plain_gamma_array_ = copy.coeff_products_mod_plain_gamma_array_;
                neg_inv_coeff_products_all_mod_plain_gamma_array_ = copy.neg_inv_coeff_products_all_mod_plain_gamma_array_;
                plain_gamma_product_mod_coeff_array_ = copy.plain_gamma_product_mod_coeff_array_;
            }
        }

        BaseConverter::BaseConverter(const std::vector<SmallModulus> &coeff_base, int coeff_count, int coeff_power, 
            const SmallModulus &small_plain_mod, const MemoryPoolHandle &pool) : pool_(pool)
        {
#ifdef SEAL_DEBUG
            if (coeff_base.size() == 0)
            {
                throw invalid_argument("coeff bases cannot be empty");
            }
#endif
            /**
            Perform all the required pre-computations and populate the tables
            */
            reset();

            m_sk_ = global_variables::internal_mods::m_sk;
            m_tilde_ = global_variables::internal_mods::m_tilde;
            gamma_ = global_variables::internal_mods::gamma;
            small_plain_mod_ = small_plain_mod;
            coeff_count_ = coeff_count;
            coeff_base_mod_count_ = coeff_base.size();
            aux_base_mod_count_ = coeff_base.size();
            
            // In some cases we might need to increase the size of the aux base by one, namely
            // we require K * n * t * q^2 < q * prod_i m_i * m_sk, where K takes into account
            // cross terms when larger size ciphertexts are used, and n is the "delta factor"
            // for the ring. We reserve 32 bits for K * n. Here the coeff modulus primes q_i
            // are bounded to be 60 bits, and all m_i, m_sk are 61 bits.
            int total_coeff_bit_count = 0;
            for (int i = 0; i < coeff_base.size(); i++)
            {
                total_coeff_bit_count += coeff_base[i].bit_count();
            }
            if (32 + small_plain_mod_.bit_count() + total_coeff_bit_count >= 61 * coeff_base.size() + 61)
            {
                aux_base_mod_count_++;
            }

            bsk_base_mod_count_ = aux_base_mod_count_ + 1;
            plain_gamma_count_ = 2;
            coeff_base_array_.resize(coeff_base_mod_count_);
            aux_base_array_.resize(aux_base_mod_count_);
            plain_gamma_array_.resize(plain_gamma_count_);
            mtilde_inv_coeff_base_products_mod_coeff_array_.resize(coeff_base_mod_count_);
            inv_aux_base_products_mod_aux_array_.resize(aux_base_mod_count_);
            inv_coeff_base_products_mod_coeff_array_.resize(coeff_base_mod_count_);
            coeff_base_products_mod_mtilde_array_.resize(coeff_base_mod_count_);
            inv_coeff_products_all_mod_aux_bsk_array_.resize(bsk_base_mod_count_);
            aux_base_products_mod_msk_array_.resize(aux_base_mod_count_);
            aux_products_all_mod_coeff_array_.resize(coeff_base_mod_count_);
            inv_mtilde_mod_bsk_array_.resize(bsk_base_mod_count_);
            coeff_products_all_mod_bsk_array_.resize(bsk_base_mod_count_);
            neg_inv_coeff_products_all_mod_plain_gamma_array_.resize(plain_gamma_count_);
            plain_gamma_product_mod_coeff_array_.resize(coeff_base_mod_count_);

            coeff_base_products_mod_aux_bsk_array_.resize(coeff_base_mod_count_);
            for (int i = 0; i < coeff_base_mod_count_; i++)
            {
                coeff_base_products_mod_aux_bsk_array_[i].resize(bsk_base_mod_count_);
            }

            aux_base_products_mod_coeff_array_.resize(aux_base_mod_count_);
            for (int i = 0; i < aux_base_mod_count_; i++)
            {
                aux_base_products_mod_coeff_array_[i].resize(coeff_base_mod_count_);
            }

            coeff_products_mod_plain_gamma_array_.resize(coeff_base_mod_count_);
            for (int i = 0; i < coeff_base_mod_count_; i++)
            {
                coeff_products_mod_plain_gamma_array_[i].resize(plain_gamma_count_);
            }

            // Copy coeff base and auxiliary base arrays
            coeff_base_array_ = coeff_base;
            for (int i = 0; i < aux_base_mod_count_; i++)
            {
                aux_base_array_[i] = global_variables::internal_mods::aux_small_mods[i];
            }
            bsk_base_array_ = aux_base_array_;
            bsk_base_array_.emplace_back(m_sk_);

            // Generate Bsk U {mtilde} small ntt tables which is used in Evaluator
            int coeff_power_count = coeff_power;
            for (int i = 0; i < bsk_base_mod_count_; i++)
            {
                bsk_small_ntt_table_.emplace_back(pool_);
                if (!bsk_small_ntt_table_[i].generate(coeff_power_count, bsk_base_array_[i]))
                {
                    reset();
                    return;
                }
            }

            // Generate plain gamma array
            plain_gamma_array_[0] = small_plain_mod_;
            plain_gamma_array_[1] = gamma_;
            
            int coeff_products_uint64_count = coeff_base_mod_count_;
            int aux_products_uint64_count = aux_base_mod_count_;
            
            Pointer coeff_products_array(allocate_zero_uint(coeff_products_uint64_count * coeff_base_mod_count_, pool_));
            Pointer tmp_coeff(allocate_uint(coeff_products_uint64_count, pool));
            
            for (int i = 0; i < coeff_base_mod_count_; i++)
            {
                coeff_products_array[i * coeff_products_uint64_count] = 1;
                for (int j = 0; j < coeff_base_mod_count_; j++)
                {
                    if (i != j)
                    {
                        multiply_uint_uint64(coeff_products_array.get() + (i * coeff_products_uint64_count), coeff_products_uint64_count, 
                            coeff_base_array_[j].value(), coeff_products_uint64_count, tmp_coeff.get());
                        set_uint_uint(tmp_coeff.get(), coeff_products_uint64_count, coeff_products_array.get() + (i * coeff_products_uint64_count));
                    }
                }
            }

            Pointer aux_products_array(allocate_zero_uint(aux_products_uint64_count * aux_base_mod_count_, pool_));
            Pointer tmp_aux(allocate_uint(aux_products_uint64_count, pool));

            for (int i = 0; i < aux_base_mod_count_; i++)
            {
                aux_products_array[i * aux_products_uint64_count] = 1;
                for (int j = 0; j < aux_base_mod_count_; j++)
                {
                    if (i != j)
                    {
                        multiply_uint_uint64(aux_products_array.get() + (i * aux_products_uint64_count), aux_products_uint64_count, 
                            aux_base_array_[j].value(), aux_products_uint64_count, tmp_aux.get());
                        set_uint_uint(tmp_aux.get(), aux_products_uint64_count, aux_products_array.get() + (i * aux_products_uint64_count));
                    }
                }
            }

            // Compute auxiliary base products mod m_sk
            for (int i = 0; i < aux_base_mod_count_; i++)
            {
                aux_base_products_mod_msk_array_[i] = modulo_uint(aux_products_array.get() + (i * aux_products_uint64_count), aux_products_uint64_count, m_sk_, pool_);
            }

            // Compute inverse coeff base mod coeff base array (qi^(-1)) mod qi and mtilde inv coeff products mod auxiliary moduli  (m_tilda*qi^(-1)) mod qi
            for (int i = 0; i < coeff_base_mod_count_; i++)
            {
                inv_coeff_base_products_mod_coeff_array_[i] = modulo_uint(coeff_products_array.get() + (i * coeff_products_uint64_count), 
                    coeff_products_uint64_count, coeff_base_array_[i], pool_);
                if (!try_invert_uint_mod(inv_coeff_base_products_mod_coeff_array_[i], coeff_base_array_[i], inv_coeff_base_products_mod_coeff_array_[i]))
                {
                    reset();
                    return;
                }
                mtilde_inv_coeff_base_products_mod_coeff_array_[i] = multiply_uint_uint_mod(inv_coeff_base_products_mod_coeff_array_[i], 
                    m_tilde_.value(), coeff_base_array_[i]);
            }
            
            // Compute inverse auxiliary moduli mod auxiliary moduli (mi^(-1)) mod mi 
            for (int i = 0; i < aux_base_mod_count_; i++)
            {
                inv_aux_base_products_mod_aux_array_[i] = modulo_uint(aux_products_array.get() + (i * aux_products_uint64_count), 
                    aux_products_uint64_count, aux_base_array_[i], pool_);
                if (!try_invert_uint_mod(inv_aux_base_products_mod_aux_array_[i], aux_base_array_[i], inv_aux_base_products_mod_aux_array_[i]))
                {
                    reset();
                    return;
                }
            }
            
            // Compute coeff modulus products mod mtilde (qi) mod m_tilde_ 
            for (int i = 0; i < coeff_base_mod_count_; i++)
            {
                coeff_base_products_mod_mtilde_array_[i] = modulo_uint(coeff_products_array.get() + (i * coeff_products_uint64_count), 
                    coeff_products_uint64_count, m_tilde_, pool_);
            }

            // Compute coeff modulus products mod auxiliary moduli (qi) mod mj U {msk}
            for (int i = 0; i < aux_base_mod_count_; i++)
            {
                for (int j = 0; j < coeff_base_mod_count_; j++)
                {
                    coeff_base_products_mod_aux_bsk_array_[j][i] = modulo_uint(coeff_products_array.get() + (j * coeff_products_uint64_count), 
                        coeff_products_uint64_count, aux_base_array_[i], pool_);
                }
            }

            // Add qi mod msk at the end of the array
            for (int i = 0; i < aux_base_mod_count_; i++)
            {
                coeff_base_products_mod_aux_bsk_array_[i][aux_base_mod_count_] = modulo_uint(coeff_products_array.get() + (i * coeff_products_uint64_count), 
                    coeff_products_uint64_count, m_sk_, pool_);
            }

            // Compute auxiliary moduli products mod coeff moduli (mj) mod qi
            for (int i = 0; i < coeff_base_mod_count_; i++)
            {
                for (int j = 0; j < aux_base_mod_count_; j++)
                {
                    aux_base_products_mod_coeff_array_[i][j] = modulo_uint(aux_products_array.get() + (j * aux_products_uint64_count), 
                        aux_products_uint64_count, coeff_base_array_[i], pool_);
                }
            }

            // Compute coeff moduli products inverse mod auxiliary mods  (qi^(-1)) mod mj U {msk} 
            Pointer coeff_products_all(allocate_uint(coeff_base_mod_count_, pool_));
            Pointer tmp_products_all(allocate_uint(coeff_base_mod_count_, pool_));
            set_uint(1, coeff_base_mod_count_, coeff_products_all.get());
            
            // Compute the product of all coeff moduli
            for (int i = 0; i < coeff_base_mod_count_; i++)
            {
                multiply_uint_uint64(coeff_products_all.get(), coeff_base_mod_count_, coeff_base_array_[i].value(), coeff_base_mod_count_, tmp_products_all.get());
                set_uint_uint(tmp_products_all.get(), coeff_base_mod_count_, coeff_products_all.get());
            }

            for (int i = 0; i < aux_base_mod_count_; i++)
            {
                inv_coeff_products_all_mod_aux_bsk_array_[i] = modulo_uint(coeff_products_all.get(), coeff_base_mod_count_, aux_base_array_[i], pool_);
                if (!try_invert_uint_mod(inv_coeff_products_all_mod_aux_bsk_array_[i], aux_base_array_[i], inv_coeff_products_all_mod_aux_bsk_array_[i]))
                {
                    reset();
                    return;
                }
            }

            // Add product of all coeffs mod msk at the end of the array
            inv_coeff_products_all_mod_aux_bsk_array_[aux_base_mod_count_] = modulo_uint(coeff_products_all.get(), coeff_base_mod_count_, m_sk_, pool_);
            if (!try_invert_uint_mod(inv_coeff_products_all_mod_aux_bsk_array_[aux_base_mod_count_], m_sk_, inv_coeff_products_all_mod_aux_bsk_array_[aux_base_mod_count_]))
            {
                reset();
                return;
            }

            // Compute the products of all aux moduli
            Pointer aux_products_all(allocate_uint(aux_base_mod_count_, pool_));
            Pointer tmp_aux_products_all(allocate_uint(aux_base_mod_count_, pool_));
            set_uint(1, aux_base_mod_count_, aux_products_all.get());

            for (int i = 0; i < aux_base_mod_count_; i++)
            {
                multiply_uint_uint64(aux_products_all.get(), aux_base_mod_count_, aux_base_array_[i].value(), aux_base_mod_count_, tmp_aux_products_all.get());
                set_uint_uint(tmp_aux_products_all.get(), aux_base_mod_count_, aux_products_all.get());
            }

            // Compute the auxiliary products inverse mod m_sk_  (M-1) mod m_sk_
            inv_aux_products_mod_msk_ = modulo_uint(aux_products_all.get(), aux_base_mod_count_, m_sk_, pool_);
            if (!try_invert_uint_mod(inv_aux_products_mod_msk_, m_sk_, inv_aux_products_mod_msk_))
            {
                reset();
                return;
            }

            // Compute auxiliary products all mod coefficient moduli
            for (int i = 0; i < coeff_base_mod_count_; i++)
            {
                aux_products_all_mod_coeff_array_[i] = modulo_uint(aux_products_all.get(), aux_base_mod_count_, coeff_base_array_[i], pool_);
            }

            uint64_t reduced_mtilde = 0;
            // Compute m_tilde inverse mod bsk base 
            for (int i = 0; i < aux_base_mod_count_; i++)
            {
                reduced_mtilde = m_tilde_.value() % aux_base_array_[i].value();
                if (!try_invert_uint_mod(reduced_mtilde, aux_base_array_[i], inv_mtilde_mod_bsk_array_[i]))
                {
                    reset();
                    return;
                }
            }

            // Add m_tilde inverse mod msk at the end of the array
            reduced_mtilde = m_tilde_.value() % m_sk_.value();
            if (!try_invert_uint_mod(reduced_mtilde, m_sk_, inv_mtilde_mod_bsk_array_[aux_base_mod_count_]))
            {
                reset();
                return;
            }

            // Compute coeff moduli products inverse mod m_tilde 
            inv_coeff_products_mod_mtilde_ = modulo_uint(coeff_products_all.get(), coeff_base_mod_count_, m_tilde_, pool_);
            if (!try_invert_uint_mod(inv_coeff_products_mod_mtilde_, m_tilde_, inv_coeff_products_mod_mtilde_))
            {
                reset();
                return;
            }

            // Compute coeff base products all mod Bsk
            for (int i = 0; i < aux_base_mod_count_; i++)
            {
                coeff_products_all_mod_bsk_array_[i] = modulo_uint(coeff_products_all.get(), coeff_base_mod_count_, aux_base_array_[i], pool_);
            }

            // Add coeff base products all mod m_sk_ at the end of the array
            coeff_products_all_mod_bsk_array_[aux_base_mod_count_] = modulo_uint(coeff_products_all.get(), coeff_base_mod_count_, m_sk_, pool_);

            // Compute coeff moduli products mod plain gamma
            for (int i = 0; i < plain_gamma_count_; i++)
            {
                for (int j = 0; j < coeff_base_mod_count_; j++)
                {
                    coeff_products_mod_plain_gamma_array_[j][i] = modulo_uint(coeff_products_array.get() + (j * coeff_products_uint64_count), 
                        coeff_products_uint64_count, plain_gamma_array_[i], pool_);
                }
            }

            // Compute inverse of all coeff moduli products mod plain gamma
            for (int i = 0; i < plain_gamma_count_; i++)
            {
                uint64_t temp = modulo_uint(coeff_products_all.get(), coeff_base_mod_count_, plain_gamma_array_[i], pool_);
                neg_inv_coeff_products_all_mod_plain_gamma_array_[i] = negate_uint_mod(temp, plain_gamma_array_[i]);
                if (!try_invert_uint_mod(neg_inv_coeff_products_all_mod_plain_gamma_array_[i], plain_gamma_array_[i], neg_inv_coeff_products_all_mod_plain_gamma_array_[i]))
                {
                    reset();
                    return;
                }
            }

            // Compute inverse of gamma mod plain modulus
            inv_gamma_mod_plain_ = modulo_uint(gamma_.pointer(), gamma_.uint64_count(), small_plain_mod_, pool_);
            if (!try_invert_uint_mod(inv_gamma_mod_plain_, small_plain_mod_, inv_gamma_mod_plain_))
            {
                reset();
                return;
            }

            // Compute plain_gamma product mod coeff base moduli
            for (int i = 0; i < coeff_base_mod_count_; i++)
            {
                plain_gamma_product_mod_coeff_array_[i] = multiply_uint_uint_mod(small_plain_mod_.value(), gamma_.value(), coeff_base_array_[i]);
            }

            // Everything went well
            generated_ = true;
        }

        void BaseConverter::reset()
        {
            generated_ = false;
            coeff_base_array_.clear();
            aux_base_array_.clear();
            bsk_base_array_.clear();
            plain_gamma_array_.clear();
            mtilde_inv_coeff_base_products_mod_coeff_array_.clear();
            inv_aux_base_products_mod_aux_array_.clear();
            inv_coeff_products_all_mod_aux_bsk_array_.clear();
            inv_coeff_base_products_mod_coeff_array_.clear();
            aux_base_products_mod_coeff_array_.clear();
            coeff_base_products_mod_aux_bsk_array_.clear();
            coeff_base_products_mod_mtilde_array_.clear();
            aux_base_products_mod_msk_array_.clear();
            aux_products_all_mod_coeff_array_.clear();
            inv_mtilde_mod_bsk_array_.clear();
            coeff_products_all_mod_bsk_array_.clear();
            coeff_products_mod_plain_gamma_array_.clear();
            neg_inv_coeff_products_all_mod_plain_gamma_array_.clear();
            plain_gamma_product_mod_coeff_array_.clear();
            bsk_small_ntt_table_.clear();
            inv_coeff_products_mod_mtilde_ = 0;
            m_tilde_ = 0;
            m_sk_ = 0;
            gamma_ = 0;
            coeff_count_ = 0;
            coeff_base_mod_count_ = 0;
            aux_base_mod_count_ = 0;
            plain_gamma_count_ = 0;
            inv_gamma_mod_plain_ = 0;
        }

        void BaseConverter::fastbconv(const uint64_t *input, uint64_t *destination, const MemoryPoolHandle &pool) const
        {
#ifdef SEAL_DEBUG
            if (input == nullptr)
            {
                throw invalid_argument("input cannot be null");
            }
            if(destination == nullptr)
            {
                throw invalid_argument("destination cannot be null");
            }
            if (!pool)
            {
                throw invalid_argument("pool is not initialied");
            }
            if (!generated_)
            {
                throw logic_error("BaseConverter is not generated");
            }
#endif
            /**
             Require: Input in q
             Ensure: Output in Bsk = {m1,...,ml} U {msk}
            */
            Pointer temp_coeff_transition(allocate_uint(coeff_count_ * coeff_base_mod_count_, pool));

            for (int i = 0; i < coeff_base_mod_count_; i++)
            {
                for (int k = 0; k < coeff_count_; k++)
                {
                    temp_coeff_transition[k + (i * coeff_count_)] = multiply_uint_uint_mod(input[k + (i * coeff_count_)], inv_coeff_base_products_mod_coeff_array_[i], coeff_base_array_[i]);
                }
            }

            for (int j = 0; j < bsk_base_mod_count_; j++)
            {
                for (int k = 0; k < coeff_count_; k++)
                {
                    uint64_t aux_transition[2]{ 0 };
                    for (int i = 0; i < coeff_base_mod_count_; i++)
                    {
                        {
                            //uint64_t aux_transition;
                            //multiply_uint64_mod(temp_coeff_transition.get() + k, &coeff_base_products_mod_aux_bsk_array_[i][j], bsk_base_array_[j], &aux_transition);
                            //add_uint_uint_smallmod(&aux_transition, destination + (k + j * coeff_count_), bsk_base_array_[j], destination + (k + j * coeff_count_));

                            // Lazy reduction
                            uint64_t temp[2];

                            // Product is 60 bit + 61 bit = 121 bit, so can sum up to 127 of them with no reduction
                            // Thus need coeff_base_mod_count_ <= 127 to guarantee success
                            multiply_uint64(temp_coeff_transition[k + (i * coeff_count_)], coeff_base_products_mod_aux_bsk_array_[i][j], temp);
                            unsigned char carry = add_uint64(aux_transition[0], temp[0], 0, aux_transition);
                            aux_transition[1] += temp[1] + carry;
                        }
                    }
                    destination[k + (j * coeff_count_)] = barrett_reduce_128(aux_transition, bsk_base_array_[j]);
                }
            }
        }

        void BaseConverter::fastbconv_sk(const uint64_t *input, uint64_t *destination, const MemoryPoolHandle &pool) const
        {
#ifdef SEAL_DEBUG
            if (input == nullptr)
            {
                throw invalid_argument("input cannot be null");
            }
            if (destination == nullptr)
            {
                throw invalid_argument("destination cannot be null");
            }
            if (!pool)
            {
                throw invalid_argument("pool is not initialied");
            }
#endif
            /**
             Require: Input in base Bsk = M U {msk}
             Ensure: Output in base q
            */

            // Fast convert B -> q
            Pointer temp_coeff_transition(allocate_uint(coeff_count_ * coeff_base_mod_count_, pool));
            for (int i = 0; i < coeff_base_mod_count_; i++)
            {
                for (int k = 0; k < coeff_count_; k++)
                {
                    temp_coeff_transition[k + (i * coeff_count_)] = multiply_uint_uint_mod(input[k + (i * coeff_count_)], inv_aux_base_products_mod_aux_array_[i], aux_base_array_[i]);
                }
            }

            for (int j = 0; j < coeff_base_mod_count_; j++)
            {
                for (int k = 0; k < coeff_count_; k++)
                {
                    uint64_t aux_transition[2]{ 0 };
                    for (int i = 0; i < aux_base_mod_count_; i++)
                    {
                        //uint64_t aux_transition;
                        //multiply_uint64_mod(temp_coeff_transition.get() + k + (i * coeff_count_), &aux_base_products_mod_coeff_array_[j][i], coeff_base_array_[j], &aux_transition);
                        //add_uint_uint_smallmod(&aux_transition, destination + (k + j * coeff_count_), coeff_base_array_[j], destination + (k + j * coeff_count_));

                        // Lazy reduction
                        uint64_t temp[2];

                        // Product is 61 bit + 60 bit = 121 bit, so can sum up to 127 of them with no reduction
                        // Thus need aux_base_mod_count_ <= 127, so coeff_base_mod_count_ <= 126 to guarantee success
                        multiply_uint64(temp_coeff_transition[k + (i * coeff_count_)], aux_base_products_mod_coeff_array_[j][i], temp);
                        unsigned char carry = add_uint64(aux_transition[0], temp[0], 0, aux_transition);
                        aux_transition[1] += temp[1] + carry;
                    }
                    destination[k + (j * coeff_count_)] = barrett_reduce_128(aux_transition, coeff_base_array_[j]);
                }
            }
            
            // Compute alpha_sk
            // Require: Input is in Bsk 
            // we only use coefficient in B 
            // Fast convert B -> m_sk
            Pointer tmp(allocate_uint(coeff_count_, pool));
            for (int k = 0; k < coeff_count_; k++)
            {
                uint64_t msk_transition[2]{ 0 };
                for (int i = 0; i < aux_base_mod_count_; i++)
                {
                    //multiply_uint64_mod(&coeff_transition, &aux_base_products_mod_msk_array_[i], m_sk_, &msk_transition);
                    //add_uint_uint_smallmod(&msk_transition, tmp.get() + k, m_sk_, tmp.get() + k);

                    // Lazy reduction
                    uint64_t temp[2];

                    // Product is 61 bit + 61 bit = 122 bit, so can sum up to 63 of them with no reduction
                    // Thus need aux_base_mod_count_ <= 63, so coeff_base_mod_count_ <= 62 to guarantee success
                    // This gives the strongest restriction on the number of coeff modulus primes
                    multiply_uint64(temp_coeff_transition[k + (i * coeff_count_)], aux_base_products_mod_msk_array_[i], temp);
                    unsigned char carry = add_uint64(msk_transition[0], temp[0], 0, msk_transition);
                    msk_transition[1] += temp[1] + carry;
                }
                tmp[k] = barrett_reduce_128(msk_transition, m_sk_);
            }

            Pointer alpha_sk(allocate_uint(coeff_count_, pool));
            // x_sk is allocated in input[aux_base_mod_count_]
            for (int i = 0; i < coeff_count_; i++)
            {
                //sub_uint_uint_smallmod(tmp.get() + i, input + i + (aux_base_mod_count_ * coeff_count_), m_sk_, tmp.get() + i);
                //multiply_uint64_mod(tmp.get() + i, &inv_aux_products_mod_msk_, m_sk_, alpha_sk.get() + i);

                // It is not necessary for the negation to be reduced modulo the small prime
                //negate_uint_smallmod(input + i + (aux_base_mod_count_ * coeff_count_), m_sk_, &negated_input);
                uint64_t negated_input = m_sk_.value() - input[i + (aux_base_mod_count_ * coeff_count_)];

                tmp[i] += negated_input;
                alpha_sk[i] = multiply_uint_uint_mod(tmp[i], inv_aux_products_mod_msk_, m_sk_);
            }
            
            uint64_t m_sk_div_2 = m_sk_.value() >> 1;

            for (int i = 0; i < coeff_base_mod_count_; i++)
            {
                for (int k = 0; k < coeff_count_; k++)
                {
                    uint64_t m_alpha_sk[2];

                    // Correcting alpha_sk since it is a centered modulo 
                    if (alpha_sk[k] > m_sk_div_2)
                    {
                        uint64_t alpha_sk_corrected = m_sk_.value() - alpha_sk[k];

                        //uint64_t m_alpha_sk;
                        //multiply_uint64_mod(&aux_products_all_mod_coeff_array_[i], &alpha_sk_corrected, coeff_base_array_[i], &m_alpha_sk);
                        //add_uint_uint_smallmod(destination + k + (i * coeff_count_), &m_alpha_sk, coeff_base_array_[i], destination + k + (i * coeff_count_));

                        // Lazy reduction
                        multiply_uint64(aux_products_all_mod_coeff_array_[i], alpha_sk_corrected, m_alpha_sk);
                        m_alpha_sk[1] += add_uint64(m_alpha_sk[0], destination[k + (i * coeff_count_)], 0, m_alpha_sk);
                        destination[k + (i * coeff_count_)] = barrett_reduce_128(m_alpha_sk, coeff_base_array_[i]);
                    }
                    // No correction needed
                    else
                    {
                        //uint64_t m_alpha_sk;
                        //multiply_uint64_mod(&aux_products_all_mod_coeff_array_[i], alpha_sk.get() + k, coeff_base_array_[i], &m_alpha_sk);
                        //sub_uint_uint_smallmod(destination + k + (i * coeff_count_), &m_alpha_sk, coeff_base_array_[i], destination + k + (i * coeff_count_));

                        // Lazy reduction
                        // It is not necessary for the negation to be reduced modulo the small prime
                        uint64_t negated_input = coeff_base_array_[i].value() - aux_products_all_mod_coeff_array_[i];
                        multiply_uint64(negated_input, alpha_sk[k], m_alpha_sk);
                        m_alpha_sk[1] += add_uint64(destination[k + (i * coeff_count_)], m_alpha_sk[0], 0, m_alpha_sk);
                        destination[k + (i * coeff_count_)] = barrett_reduce_128(m_alpha_sk, coeff_base_array_[i]);
                    }
                }
            }
        }

        void BaseConverter::mont_rq(const uint64_t *input, uint64_t *destination) const
        {
#ifdef SEAL_DEBUG
            if (input == nullptr)
            {
                throw invalid_argument("input cannot be null");
            }
            if (destination == nullptr)
            {
                throw invalid_argument("destination cannot be null");
            }
#endif
            /**
             Require: Input should in Bsk U {m_tilde}
             Ensure: Destination array in Bsk = m U {msk}
            */
                        
            for (int i = 0; i < coeff_count_; i++)
            {
                // Compute r_mtilde
                uint64_t r_mtilde = multiply_uint_uint_mod(input[i + (coeff_count_ * bsk_base_mod_count_)], inv_coeff_products_mod_mtilde_, m_tilde_);
                r_mtilde = negate_uint_mod(r_mtilde, m_tilde_);

                // Compute result for aux base
                for (int k = 0; k < bsk_base_mod_count_; k++)
                {
                    //uint64_t tmp;
                    //multiply_uint64_mod(&coeff_products_all_mod_bsk_array_[k], &r_mtilde, bsk_base_array_[k], &tmp);
                    //add_uint_uint_smallmod(input + i + (k * coeff_count_), &tmp, bsk_base_array_[k], &tmp);
                    //multiply_uint64_mod(&tmp, &inv_mtilde_mod_bsk_array_[k], bsk_base_array_[k], destination + i + (k * coeff_count_));

                    // Lazy reduction
                    uint64_t tmp[2];
                    multiply_uint64(coeff_products_all_mod_bsk_array_[k], r_mtilde, tmp);
                    tmp[1] += add_uint64(tmp[0], input[i + (k * coeff_count_)], 0, tmp);
                    uint64_t tmp2 = barrett_reduce_128(tmp, bsk_base_array_[k]);
                    destination[i + (k * coeff_count_)] = multiply_uint_uint_mod(tmp2, inv_mtilde_mod_bsk_array_[k], bsk_base_array_[k]);
                }
            }
        }

        void BaseConverter::fast_floor(const uint64_t *input, uint64_t *destination, const MemoryPoolHandle &pool) const
        {
#ifdef SEAL_DEBUG
            if (input == nullptr)
            {
                throw invalid_argument("input cannot be null");
            }
            if (destination == nullptr)
            {
                throw invalid_argument("destination cannot be null");
            }
            if (!pool)
            {
                throw invalid_argument("pool is not initialied");
            }
#endif
            /** 
             Require: Input in q U m U {msk}
             Ensure: Destination array in Bsk
            */
            fastbconv(input, destination, pool); //q -> Bsk
            
            int index_msk = coeff_base_mod_count_ * coeff_count_;
            
            for (int i = 0; i < bsk_base_mod_count_; i++)
            {
                for (int k = 0; k < coeff_count_; k++)
                {
                    //uint64_t tmp;
                    //sub_uint_uint_smallmod(input + index_msk + k + (i * coeff_count_), base_convert_Bsk.get() + k + (i * coeff_count_), bsk_base_array_[i], &tmp);
                    //multiply_uint64_mod(&tmp, &inv_coeff_products_all_mod_aux_bsk_array_[i], bsk_base_array_[i], destination + k + (i * coeff_count_));

                    uint64_t bsk_transition;

                    // It is not necessary for the negation to be reduced modulo the small prime
                    //negate_uint_smallmod(base_convert_Bsk.get() + k + (i * coeff_count_), bsk_base_array_[i], &negated_base_convert_Bsk);
                    uint64_t negated_base_convert_Bsk = bsk_base_array_[i].value() - destination[k + (i * coeff_count_)];

                    bsk_transition = input[index_msk + k + (i * coeff_count_)] + negated_base_convert_Bsk;
                    destination[k + (i * coeff_count_)] = multiply_uint_uint_mod(bsk_transition, inv_coeff_products_all_mod_aux_bsk_array_[i], bsk_base_array_[i]);
                }
            }
        }

        void BaseConverter::fastbconv_mtilde(const uint64_t *input, uint64_t *destination, const MemoryPoolHandle &pool) const
        {
#ifdef SEAL_DEBUG
            if (input == nullptr)
            {
                throw invalid_argument("input cannot be null");
            }
            if (destination == nullptr)
            {
                throw invalid_argument("destination cannot be null");
            }
            if (!pool)
            {
                throw invalid_argument("pool is not initialied");
            }
#endif
            /**
             Require: Input in q
             Ensure: Output in Bsk U {m_tilde}
            */
            
            // Compute in Bsk first; we compute |m_tilde*q^-1i| mod qi
            Pointer temp_coeff_transition(allocate_uint(coeff_count_ * coeff_base_mod_count_, pool));
            for (int i = 0; i < coeff_base_mod_count_; i++)
            {
                for (int k = 0; k < coeff_count_; k++)
                {
                    temp_coeff_transition[k + (i * coeff_count_)] = multiply_uint_uint_mod(input[k + (i * coeff_count_)], 
                        mtilde_inv_coeff_base_products_mod_coeff_array_[i], coeff_base_array_[i]);
                }
            }

            for (int j = 0; j < bsk_base_mod_count_; j++)
            {
                for (int k = 0; k < coeff_count_; k++)
                {
                    uint64_t aux_transition[2]{ 0 };
                    for (int i = 0; i < coeff_base_mod_count_; i++)
                    {
                        //uint64_t aux_transition;
                        //multiply_uint64_mod(temp_coeff_transition.get() + k + (i * coeff_count_), 
                        //  &coeff_base_products_mod_aux_bsk_array_[i][j], bsk_base_array_[j], &aux_transition);
                        //add_uint_uint_smallmod(&aux_transition, destination + (k + j * coeff_count_), bsk_base_array_[j], 
                        // destination + (k + j * coeff_count_));

                        // Lazy reduction
                        uint64_t temp[2];

                        // Product is 60 bit + 61 bit = 121 bit, so can sum up to 127 of them with no reduction
                        // Thus need coeff_base_mod_count_ <= 127
                        multiply_uint64(temp_coeff_transition[k + (i * coeff_count_)], 
                            coeff_base_products_mod_aux_bsk_array_[i][j], temp);
                        unsigned char carry = add_uint64(aux_transition[0], temp[0], 0, aux_transition);
                        aux_transition[1] += temp[1] + carry;
                    }
                    destination[k + (j * coeff_count_)] = barrett_reduce_128(aux_transition, bsk_base_array_[j]);
                }
            }

            int index_mtilde = bsk_base_mod_count_ * coeff_count_;
            
            // Computing the last element (mod m_tilde) and add it at the end of destination array
            for (int k = 0; k < coeff_count_; k++)
            {
                uint64_t wide_result[2]{ 0 };
                for (int i = 0; i < coeff_base_mod_count_; i++)
                {
                    // Lazy reduction
                    uint64_t aux_transition[2];

                    // Product is 60 bit + 33 bit = 93 bit
                    multiply_uint64(temp_coeff_transition[k + (i * coeff_count_)], 
                        coeff_base_products_mod_mtilde_array_[i], aux_transition);
                    unsigned char carry = add_uint64(aux_transition[0], wide_result[0], 0, wide_result);
                    wide_result[1] += aux_transition[1] + carry;
                }
                destination[index_mtilde + k] = barrett_reduce_128(wide_result, m_tilde_);
            }
        }

        void BaseConverter::fastbconv_plain_gamma(const uint64_t *input, uint64_t *destination) const
        {
#ifdef SEAL_DEBUG
            if (input == nullptr)
            {
                throw invalid_argument("input cannot be null");
            }
            if (destination == nullptr)
            {
                throw invalid_argument("destination cannot be null");
            }
#endif
            /**
             Require: Input in q
             Ensure: Output in t (plain modulus) U gamma 
            */
            for (int k = 0; k < coeff_count_; k++)
            {
                uint64_t wide_result[4]{ 0 };
                for (int i = 0; i < coeff_base_mod_count_; i++)
                {
                    uint64_t temp_coeff_transition = multiply_uint_uint_mod(input[k + (i * coeff_count_)], 
                        inv_coeff_base_products_mod_coeff_array_[i], coeff_base_array_[i]);
                    
                    for (int j = 0; j < plain_gamma_count_; j++)
                    {
                        // Lazy reduction
                        uint64_t plain_transition[2];

                        // Product is 60 bit + 61 bit = 121 bit, so can sum up to 127 of them with no reduction
                        // Thus need coeff_base_mod_count_ <= 127
                        multiply_uint64(temp_coeff_transition, coeff_products_mod_plain_gamma_array_[i][j], plain_transition);
                        unsigned char carry = add_uint64(plain_transition[0], wide_result[2 * j], 0, wide_result + (2 * j));
                        wide_result[2 * j + 1] += plain_transition[1] + carry;
                    }
                }

                for (int j = 0; j < plain_gamma_count_; j++)
                {
                    destination[k + (j * coeff_count_)] = barrett_reduce_128(wide_result + (2 * j), plain_gamma_array_[j]);
                }
            }
        }
    }
}
