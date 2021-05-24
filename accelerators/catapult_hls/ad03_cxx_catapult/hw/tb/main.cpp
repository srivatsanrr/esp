//#include "../inc/espacc_config.h"
//#include "../inc/espacc.h"

#include "ad03_cxx_catapult.hpp"
#include "esp_headers.hpp" // ESP-common headers

#include <cstdlib>
#include <cstdio>

#include <mc_scverify.h>   // Enable SCVerify

//void softmax_tb(FPDATA_IN *input, double *output) {
//    double exp_in[PLM_SIZE];
//    double sum_exp = 0;
//    for (unsigned i = 0; i < PLM_SIZE; i++) {
//        exp_in[i] = exp(input[i].to_double());
//        sum_exp += exp_in[i];
//    }
//    for (unsigned i = 0; i < PLM_SIZE; i++) { output[i] = exp_in[i]/sum_exp; }
//}
//
double abs_double(const double &input)
{
    return input < 0 ? -input : input;
}

// This can be read from a file (and should)
static char raw_inputs[10][128] {
{ -53, -2, -6, -4, -19, -17, -17, -22, -16, -19, -22, -27, -25, -25, -25, -31, -27, -37, -36, -35, -36, -34, -39, -37, -40, -40, -43, -43, -43, -42, -43, -38, -53, -4, -10, -1, -10, -17, -19, -18, -15, -26, -27, -24, -32, -25, -23, -36, -28, -35, -31, -37, -41, -42, -43, -35, -35, -37, -38, -39, -41, -41, -44, -35, -41, -2, -18, -13, -13, -9, -22, -21, -12, -24, -18, -23, -29, -26, -29, -37, -32, -28, -33, -34, -36, -38, -36, -40, -30, -37, -42, -43, -42, -38, -40, -38, -46, -2, -8, -15, -15, -13, -31, -29, -21, -27, -25, -27, -30, -29, -29, -32, -30, -39, -34, -34, -40, -40, -42, -38, -40, -41, -41, -42, -42, -42, -44, -38, },
{ -53, -4, -10, -1, -10, -17, -19, -18, -15, -26, -27, -24, -32, -25, -23, -36, -28, -35, -31, -37, -41, -42, -43, -35, -35, -37, -38, -39, -41, -41, -44, -35, -41, -2, -18, -13, -13, -9, -22, -21, -12, -24, -18, -23, -29, -26, -29, -37, -32, -28, -33, -34, -36, -38, -36, -40, -30, -37, -42, -43, -42, -38, -40, -38, -46, -2, -8, -15, -15, -13, -31, -29, -21, -27, -25, -27, -30, -29, -29, -32, -30, -39, -34, -34, -40, -40, -42, -38, -40, -41, -41, -42, -42, -42, -44, -38, -45, -3, -15, -5, -12, -16, -23, -22, -14, -25, -22, -27, -30, -28, -26, -32, -32, -38, -30, -39, -38, -36, -44, -39, -36, -36, -40, -44, -42, -43, -41, -37, },
{ -41, -2, -18, -13, -13, -9, -22, -21, -12, -24, -18, -23, -29, -26, -29, -37, -32, -28, -33, -34, -36, -38, -36, -40, -30, -37, -42, -43, -42, -38, -40, -38, -46, -2, -8, -15, -15, -13, -31, -29, -21, -27, -25, -27, -30, -29, -29, -32, -30, -39, -34, -34, -40, -40, -42, -38, -40, -41, -41, -42, -42, -42, -44, -38, -45, -3, -15, -5, -12, -16, -23, -22, -14, -25, -22, -27, -30, -28, -26, -32, -32, -38, -30, -39, -38, -36, -44, -39, -36, -36, -40, -44, -42, -43, -41, -37, -47, -8, -22, -8, -20, -9, -23, -25, -19, -23, -21, -23, -27, -25, -33, -32, -35, -34, -38, -35, -39, -40, -39, -39, -38, -38, -40, -40, -41, -44, -39, -38, },
{ -46, -2, -8, -15, -15, -13, -31, -29, -21, -27, -25, -27, -30, -29, -29, -32, -30, -39, -34, -34, -40, -40, -42, -38, -40, -41, -41, -42, -42, -42, -44, -38, -45, -3, -15, -5, -12, -16, -23, -22, -14, -25, -22, -27, -30, -28, -26, -32, -32, -38, -30, -39, -38, -36, -44, -39, -36, -36, -40, -44, -42, -43, -41, -37, -47, -8, -22, -8, -20, -9, -23, -25, -19, -23, -21, -23, -27, -25, -33, -32, -35, -34, -38, -35, -39, -40, -39, -39, -38, -38, -40, -40, -41, -44, -39, -38, -53, -8, -10, -17, -9, -18, -15, -23, -12, -21, -22, -34, -22, -23, -28, -30, -32, -37, -34, -36, -40, -40, -39, -38, -37, -39, -47, -45, -41, -41, -40, -38, },
{ -45, -3, -15, -5, -12, -16, -23, -22, -14, -25, -22, -27, -30, -28, -26, -32, -32, -38, -30, -39, -38, -36, -44, -39, -36, -36, -40, -44, -42, -43, -41, -37, -47, -8, -22, -8, -20, -9, -23, -25, -19, -23, -21, -23, -27, -25, -33, -32, -35, -34, -38, -35, -39, -40, -39, -39, -38, -38, -40, -40, -41, -44, -39, -38, -53, -8, -10, -17, -9, -18, -15, -23, -12, -21, -22, -34, -22, -23, -28, -30, -32, -37, -34, -36, -40, -40, -39, -38, -37, -39, -47, -45, -41, -41, -40, -38, -45, -3, -12, -9, -10, -17, -21, -20, -16, -22, -18, -21, -27, -29, -33, -33, -25, -32, -24, -30, -37, -35, -41, -40, -35, -37, -48, -38, -41, -42, -43, -40, },
{ -47, -8, -22, -8, -20, -9, -23, -25, -19, -23, -21, -23, -27, -25, -33, -32, -35, -34, -38, -35, -39, -40, -39, -39, -38, -38, -40, -40, -41, -44, -39, -38, -53, -8, -10, -17, -9, -18, -15, -23, -12, -21, -22, -34, -22, -23, -28, -30, -32, -37, -34, -36, -40, -40, -39, -38, -37, -39, -47, -45, -41, -41, -40, -38, -45, -3, -12, -9, -10, -17, -21, -20, -16, -22, -18, -21, -27, -29, -33, -33, -25, -32, -24, -30, -37, -35, -41, -40, -35, -37, -48, -38, -41, -42, -43, -40, -44, -5, -6, -5, -15, -15, -21, -17, -18, -21, -19, -33, -24, -28, -28, -33, -33, -35, -35, -40, -32, -40, -42, -38, -40, -39, -43, -37, -40, -42, -40, -38, },
{ -53, -8, -10, -17, -9, -18, -15, -23, -12, -21, -22, -34, -22, -23, -28, -30, -32, -37, -34, -36, -40, -40, -39, -38, -37, -39, -47, -45, -41, -41, -40, -38, -45, -3, -12, -9, -10, -17, -21, -20, -16, -22, -18, -21, -27, -29, -33, -33, -25, -32, -24, -30, -37, -35, -41, -40, -35, -37, -48, -38, -41, -42, -43, -40, -44, -5, -6, -5, -15, -15, -21, -17, -18, -21, -19, -33, -24, -28, -28, -33, -33, -35, -35, -40, -32, -40, -42, -38, -40, -39, -43, -37, -40, -42, -40, -38, -42, -7, -6, -13, -23, -15, -18, -15, -16, -21, -26, -24, -21, -26, -30, -32, -35, -37, -30, -31, -36, -39, -40, -38, -38, -37, -41, -38, -42, -41, -44, -39, },
{ -45, -3, -12, -9, -10, -17, -21, -20, -16, -22, -18, -21, -27, -29, -33, -33, -25, -32, -24, -30, -37, -35, -41, -40, -35, -37, -48, -38, -41, -42, -43, -40, -44, -5, -6, -5, -15, -15, -21, -17, -18, -21, -19, -33, -24, -28, -28, -33, -33, -35, -35, -40, -32, -40, -42, -38, -40, -39, -43, -37, -40, -42, -40, -38, -42, -7, -6, -13, -23, -15, -18, -15, -16, -21, -26, -24, -21, -26, -30, -32, -35, -37, -30, -31, -36, -39, -40, -38, -38, -37, -41, -38, -42, -41, -44, -39, -48, -17, -12, -5, -11, -7, -19, -25, -20, -11, -18, -25, -25, -27, -29, -36, -28, -31, -30, -32, -31, -38, -35, -42, -36, -41, -41, -40, -38, -43, -41, -40, },
{ -44, -5, -6, -5, -15, -15, -21, -17, -18, -21, -19, -33, -24, -28, -28, -33, -33, -35, -35, -40, -32, -40, -42, -38, -40, -39, -43, -37, -40, -42, -40, -38, -42, -7, -6, -13, -23, -15, -18, -15, -16, -21, -26, -24, -21, -26, -30, -32, -35, -37, -30, -31, -36, -39, -40, -38, -38, -37, -41, -38, -42, -41, -44, -39, -48, -17, -12, -5, -11, -7, -19, -25, -20, -11, -18, -25, -25, -27, -29, -36, -28, -31, -30, -32, -31, -38, -35, -42, -36, -41, -41, -40, -38, -43, -41, -40, -48, -7, -4, -4, -15, -15, -21, -16, -21, -10, -23, -26, -27, -23, -29, -33, -33, -32, -32, -35, -34, -40, -38, -40, -39, -39, -43, -38, -43, -44, -40, -38, },
{ -42, -7, -6, -13, -23, -15, -18, -15, -16, -21, -26, -24, -21, -26, -30, -32, -35, -37, -30, -31, -36, -39, -40, -38, -38, -37, -41, -38, -42, -41, -44, -39, -48, -17, -12, -5, -11, -7, -19, -25, -20, -11, -18, -25, -25, -27, -29, -36, -28, -31, -30, -32, -31, -38, -35, -42, -36, -41, -41, -40, -38, -43, -41, -40, -48, -7, -4, -4, -15, -15, -21, -16, -21, -10, -23, -26, -27, -23, -29, -33, -33, -32, -32, -35, -34, -40, -38, -40, -39, -39, -43, -38, -43, -44, -40, -38, -50, -7, -12, -8, -13, -17, -19, -24, -16, -18, -22, -27, -22, -27, -26, -26, -33, -35, -29, -34, -37, -37, -39, -41, -35, -38, -40, -37, -38, -43, -39, -40 }};

#ifdef __CUSTOM_SIM__
int sc_main(int argc, char **argv) {
#else
CCS_MAIN(int argc, char **argv) {
#endif
    ESP_REPORT_INFO(VON, "--------------------------------");
    ESP_REPORT_INFO(VON, "ESP - AD03 [Catapult HLS C++]");
#ifdef HIERARCHICAL_BLOCKS
    ESP_REPORT_INFO(VON, "      Hierarchical blocks");
#else
    ESP_REPORT_INFO(VON, "      Single block");
#endif
    ESP_REPORT_INFO(VON, "--------------------------------");

    const unsigned ad03_size = PLM_SIZE;

    // Testbench return value (0 = PASS, non-0 = FAIL)
    int rc = 0;

    // Accelerator configuration
    ac_channel<conf_info_t> conf_info;

    conf_info_t conf_info_data;
    conf_info_data.batch = 1;
    conf_info_data.mode = 0;

    // Communication channels
    ac_channel<dma_info_t> dma_read_ctrl;
    ac_channel<dma_info_t> dma_write_ctrl;
    ac_channel<dma_data_t> dma_read_chnl;
    ac_channel<dma_data_t> dma_write_chnl;

    // Accelerator done (workaround)
    ac_sync acc_done;

    // Testbench data
    FPDATA_IN inputs[PLM_SIZE * BATCH_MAX];
    FPDATA_OUT outputs[PLM_SIZE * BATCH_MAX];
    double gold_outputs[PLM_SIZE * BATCH_MAX];

    ESP_REPORT_INFO(VON, "Configuration:");
    ESP_REPORT_INFO(VON, "  - batch: %u", ESP_TO_UINT32(conf_info_data.batch));
    ESP_REPORT_INFO(VON, "  - mode: %u", ESP_TO_UINT32(conf_info_data.mode));
    ESP_REPORT_INFO(VON, "Other info:");
    ESP_REPORT_INFO(VON, "  - DMA width: %u", DMA_WIDTH);
    ESP_REPORT_INFO(VON, "  - DMA size [0=8b, 1=16b, 2=32b, 3=64b]: %u", DMA_SIZE);
    ESP_REPORT_INFO(VON, "  - PLM size: %u", PLM_SIZE);
    ESP_REPORT_INFO(VON, "  - PLM width: %u", PLM_WIDTH);
    ESP_REPORT_INFO(VON, "  - AD03 size: %u", ad03_size);
    ESP_REPORT_INFO(VON, "  - memory in (words): %u", ad03_size * ESP_TO_UINT32(conf_info_data.batch));
    ESP_REPORT_INFO(VON, "  - memory out (words): %u", ad03_size * ESP_TO_UINT32(conf_info_data.batch));
    ESP_REPORT_INFO(VON, "-----------------");

#if 0
    for (unsigned i = 0; i < 8192; i++) {
        weight2_t w = 0.0;
        ac_int<DMA_WIDTH, false> w_ac;
        w_ac.set_slc(0, w.template slc<weight2_t::width>(0));
        dma_read_chnl.write(w_ac);
    }

    for (unsigned i = 0; i < 64; i++) {
        bias2_t b = 0.0;
        ac_int<DMA_WIDTH, false> b_ac;
        b_ac.set_slc(0, b.template slc<bias2_t::width>(0));
        dma_read_chnl.write(b_ac);
    }

    for (unsigned i = 0; i < 64; i++) {
        batch_normalization_scale_t bns = 0.0;
        ac_int<DMA_WIDTH, false> bns_ac;
        b_ac.set_slc(0, bns.template slc<batch_normalization_scale_t::width>(0));
        dma_read_chnl.write(bns_ac);
    }
#endif

    // Pass inputs to the accelerator
    for (unsigned i = 0; i < conf_info_data.batch; i++) {
        for (unsigned j = 0; j < ad03_size; j+=2) {
            FPDATA_IN data_fp_lo = raw_inputs[i][j];
            FPDATA_IN data_fp_hi = raw_inputs[i][j+1];
            inputs[i * ad03_size + j] = data_fp_lo;
            inputs[i * ad03_size + j+1] = data_fp_hi;

            ac_int<DMA_WIDTH, false> data_ac;
            data_ac.set_slc(0, inputs[i * ad03_size + j].template slc<WL>(0));
            data_ac.set_slc(WL, inputs[i * ad03_size + j+1].template slc<WL>(0));

            dma_read_chnl.write(data_ac);
        }
    }
    // Pass configuration to the accelerator
    conf_info.write(conf_info_data);

    // Run the accelerator
    ad03_cxx_catapult(conf_info, dma_read_ctrl, dma_write_ctrl, dma_read_chnl, dma_write_chnl, acc_done);

    // Fetch outputs from the accelerator
    while (!dma_write_chnl.available(conf_info_data.batch * (ad03_size/2))) {} // Testbench stalls until data ready
    for (unsigned i = 0; i < conf_info_data.batch * ad03_size; i+=2) {
        ac_int<DMA_WIDTH, false> data = dma_write_chnl.read().template slc<DMA_WIDTH>(0);
        ac_int<WL, false> data_lo = data.template slc<DMA_WIDTH>(0);
        ac_int<WL, false> data_hi = data.template slc<DMA_WIDTH>(WL);
        outputs[i].template set_slc<WL>(0, data_lo);
        outputs[i+1].template set_slc<WL>(0, data_hi);
    }

    // Validation
    unsigned errors = 0;
#if 0
    ESP_REPORT_INFO(VON, "-----------------");
    for (unsigned i = 0; i < conf_info_data.batch; i++) {
        softmax_tb(inputs + i * softmax_size, gold_outputs + i * softmax_size);
    }
#endif

    double allowed_error = 0.001;

    for (unsigned i = 0; i < conf_info_data.batch * ad03_size; i++) {
        FPDATA_OUT gold = inputs[i];
        FPDATA_OUT data = outputs[i];

        // Calculate absolute error
        double error_it = abs_double(data.to_double() - gold.to_double());

        if (error_it > allowed_error) {
            ESP_REPORT_INFO(VON, "[%u]: %d (expected %d)", i, (char)data.to_int(), (char)gold.to_int());
            errors++;
        }
    }

    if (errors > 0) {
        ESP_REPORT_INFO(VON, "Validation: FAIL (errors %u / total %u)", errors, PLM_SIZE);
        rc = 1;
    } else {
        ESP_REPORT_INFO(VON, "Validation: PASS");
        rc = 0;
    }
    ESP_REPORT_INFO(VON, "  - errors %u / total %u", errors, PLM_SIZE);
    ESP_REPORT_INFO(VON, "-----------------");

#ifdef __CUSTOM_SIM__
    return rc;
#else
    CCS_RETURN(rc);
#endif
}
