pub use crate::custom_types::FilterValue;
use crate::disassembly::Disassembly;
pub use crate::simulation::FaultType;
pub use crate::simulation::FlagsCPSR;
pub use crate::simulation::FaultData;
use crate::simulation::*;

use std::io::stdout;
use std::io::{self, Write};
use std::error::Error;
use addr2line::gimli;
use csv::Writer;
use rand::Rng;

use rayon::prelude::*;
use strum::IntoEnumIterator;

use std::sync::mpsc::{channel, Sender};
use std::collections::HashMap;

use indicatif::ProgressBar;

use itertools::Itertools;

use log::debug;

pub struct FaultAttacks {
    cs: Disassembly,
    pub file_data: ElfFile,
    fault_data: Vec<Vec<FaultData>>,
    pub count_sum: usize,
    failed: usize
}

impl FaultAttacks {
    pub fn new(path: std::path::PathBuf) -> Result<Self, String> {
        // Load victim data
        let file_data: ElfFile = ElfFile::new(path)?;

        Ok(Self {
            cs: Disassembly::new(),
            file_data,
            fault_data: Vec::new(),
            count_sum: 0,
            failed: 0,
        })
    }

    pub fn print_fault_data(
        &self,
        debug_context: &addr2line::Context<
            gimli::EndianReader<gimli::RunTimeEndian, std::rc::Rc<[u8]>>,
        >,

    ) {
        self.cs.print_fault_records(&self.fault_data, debug_context);
    }

    pub fn write_attack_data(
        &self,
        cycles: usize,
        deep_analysis: bool,
        len: usize,
        total_executed: usize,
        data_analysis: Vec<(Vec<Vec<FaultData>>, usize)>,
    ) -> Result<(), Box<dyn Error>>{
        let mut instruction_rel: HashMap<String, f64> = HashMap::new();

        print!("\nFile path for data (Return for no existing file): ");
        stdout().flush().unwrap();
        let mut buffer = String::new();

        if io::stdin().read_line(&mut buffer).is_ok() {
            if let Ok(file_path) = buffer.trim().parse::<String>() {
                let mut writer_1 = Writer::from_path(format!("{file_path}.csv"))?;
                writer_1.write_record(&["Attack Vectors", "Successful Attacks", "Executed Attacks", "Success Rate (%)", "Targeted Instructions"])?;

                let mut total_success = 0;
                for (fault_data, failed) in data_analysis.clone() {
                    self.cs.write_fault_records(len, &fault_data, &mut writer_1, failed, &mut instruction_rel)?;
                    total_success += fault_data.len();
                }
                writer_1.flush()?;

                let mut writer_2 = Writer::from_path(format!("{file_path}_rel.csv"))?;
                writer_2.write_record(&["Instruction", "Targeted", "Relative"])?;

                let trace_records = trace_run(
                    &self.file_data,
                    cycles,
                    RunType::RecordTrace,
                    deep_analysis,
                    &[],
                )?;

                // Get probability per attack, since we execute len attacks
                for p in instruction_rel.values_mut() {
                    *p /= len as f64;
                }                
                
                self.cs.write_instruction_information(trace_records,  instruction_rel, data_analysis.len(), &mut writer_2)?;

                writer_2.flush()?;

                let mut writer_3 = Writer::from_path(format!("{file_path}_total.csv"))?;
                writer_3.write_record(&["#Successful", "#Executed", "Successrate (%)"])?;

                writer_3.write_record(&[
                    total_success.to_string(),
                    total_executed.to_string(),
                    format!("{:.1$}", (total_success as f64) / (total_executed as f64) * 100.0, 10).to_string()
                ])?;

                writer_3.flush()?;
            }
        }

        Ok(())
    }

    pub fn print_trace_for_fault(&self, cycles: usize, attack_number: usize) -> Result<(), String> {
        if !self.fault_data.is_empty() {
            let fault_records = FaultData::get_simulation_fault_records(
                self.fault_data.get(attack_number).unwrap(),
            );
            // Run full trace
            let trace_records = Some(trace_run(
                &self.file_data,
                cycles,
                RunType::RecordFullTrace,
                true,
                &fault_records,
            )?);
            // Print trace
            println!("\nAssembler trace of attack number {}", attack_number + 1);

            self.cs.disassembly_trace_records(&trace_records);
        }
        Ok(())
    }

    pub fn check_for_correct_behavior(&self, cycles: usize) -> Result<(), String> {
        // Get trace data from negative run
        let mut simulation = Control::new(&self.file_data);
        simulation.check_program(cycles)
    }

    /// Run single glitch attacks
    ///
    /// Parameter is the range of the single glitch size in commands
    /// Return (success: bool, number_of_attacks: usize)
    pub fn single_glitch(
        &mut self,
        cycles: usize,
        deep_analysis: bool,
        to_filter: FilterValue,
        prograss_bar: bool,
        range: std::ops::RangeInclusive<usize>,
    ) -> Result<(bool, usize), String> {
        // Run cached single nop simulation
        for i in range {
            self.fault_data = self.fault_simulation(
                cycles,
                &[FaultType::Glitch(i)],
                deep_analysis,
                to_filter,
                prograss_bar,
            )?;

            if !self.fault_data.is_empty() {
                break;
            }
        }

        Ok((!self.fault_data.is_empty(), self.count_sum))
    }

    /// Run double glitch attacks
    ///
    /// Parameter is the range of the double glitch size in commands
    /// Return (success: bool, number_of_attacks: usize)
    pub fn double_glitch(
        &mut self,
        cycles: usize,
        deep_analysis: bool,
        to_filter: FilterValue,
        prograss_bar: bool,
        range: std::ops::RangeInclusive<usize>,
    ) -> Result<(bool, usize), String> {
        // Run cached double nop simulation
        let it = range.clone().cartesian_product(range);
        for t in it {
            self.fault_data = self.fault_simulation(
                cycles,
                &[FaultType::Glitch(t.0), FaultType::Glitch(t.1)],
                deep_analysis,
                to_filter,
                prograss_bar,
            )?;

            if !self.fault_data.is_empty() {
                break;
            }
        }

        Ok((!self.fault_data.is_empty(), self.count_sum))
    }

    /// Run single bit flip attacks
    ///
    /// Return (success: bool, number_of_attacks: usize)
    pub fn single_bit_flip(
        &mut self,
        cycles: usize,
        deep_analysis: bool,
        to_filter: FilterValue,
        prograss_bar: bool,
    ) -> Result<(bool, usize), String> {
        for flg in FlagsCPSR::iter() {
            self.fault_data =
                self.fault_simulation(cycles, &[FaultType::BitFlip(flg)], deep_analysis, to_filter, prograss_bar)?;

            if !self.fault_data.is_empty() {
                break;
            }
        }

        Ok((!self.fault_data.is_empty(), self.count_sum))
    }

    /// Run custom faults of arbitrary length and fault type
    /// 
    /// Parameter is the attack vector in commands
    /// Return (success: bool, number_of_attacks: usize)
    pub fn custom_faults(
        &mut self,
        cycles: usize,
        low_complexity: bool,
        args_input: &[String],
        to_filter: FilterValue,
        prograss_bar: bool
    ) -> Result<(bool, usize, Vec<(Vec<Vec<FaultData>>, usize)>), String> {
        let args_sim: Vec<FaultType> = Vec::new();
        let mut data_analysis:Vec<(Vec<Vec<FaultData>>, usize)> = Vec::new();

        self.fault_data = self.custom_faults_inner(cycles, low_complexity, args_input, args_sim, &mut data_analysis, to_filter, prograss_bar)?;

        Ok((!data_analysis.is_empty(), self.count_sum, data_analysis))
        // Ok((!self.fault_data.is_empty(), self.count_sum, data_analysis))
    }

    fn custom_faults_inner(
        &mut self,
        cycles: usize,
        low_complexity: bool,
        args_input: &[String],
        args_sim: Vec<FaultType>,
        data_analysis: &mut Vec<(Vec<Vec<FaultData>>, usize)>,
        to_filter: FilterValue,
        prograss_bar: bool,
    ) -> Result<Vec<Vec<FaultData>>, String> {
        if args_input.is_empty() {
            self.fault_data =
                self.fault_simulation(cycles, &args_sim, low_complexity, to_filter, prograss_bar)?;

            // only add successfull attacks to the analysis
            if !self.fault_data.is_empty() {
                data_analysis.push((self.fault_data.clone(), self.failed));
            }
            return Ok(self.fault_data.clone());
        }
        
        let (&ref fault, remaining_input) = args_input.split_first().unwrap();
    
        match fault.as_str() {
            "All" => {
                for i in 1..11 {
                    let mut data = args_sim.clone();
                    data.push(FaultType::Glitch(i));
                    self.fault_data = self.custom_faults_inner(cycles, low_complexity, remaining_input, data, data_analysis, to_filter, prograss_bar)?;
                }
                for flg in FlagsCPSR::iter() {
                    let mut data = args_sim.clone();
                    data.push(FaultType::BitFlip(flg));
                    self.fault_data = self.custom_faults_inner(cycles, low_complexity, remaining_input, data, data_analysis, to_filter, prograss_bar)?;
                }
            },
            "Glitch" => {
                for i in 1..11 {
                    let mut data = args_sim.clone();
                    data.push(FaultType::Glitch(i));
                    self.fault_data = self.custom_faults_inner(cycles, low_complexity, remaining_input, data, data_analysis, to_filter, prograss_bar)?;
                }
            },
            "Bitflip" => {
                for flg in FlagsCPSR::iter() {
                    let mut data = args_sim.clone();
                    data.push(FaultType::BitFlip(flg));
                    self.fault_data = self.custom_faults_inner(cycles, low_complexity, remaining_input, data, data_analysis, to_filter, prograss_bar)?;
                }
            },
            "Glitch1" => {
                let mut data = args_sim.clone();
                data.push(FaultType::Glitch(1));
                self.fault_data = self.custom_faults_inner(cycles, low_complexity, remaining_input, data, data_analysis, to_filter, prograss_bar)?;
            },
            "Glitch2" => {
                let mut data = args_sim.clone();
                data.push(FaultType::Glitch(2));
                self.fault_data = self.custom_faults_inner(cycles, low_complexity, remaining_input, data, data_analysis, to_filter, prograss_bar)?;
            },
            "Glitch3" => {
                let mut data = args_sim.clone();
                data.push(FaultType::Glitch(3));
                self.fault_data = self.custom_faults_inner(cycles, low_complexity, remaining_input, data, data_analysis, to_filter, prograss_bar)?;
            },
            "Glitch4" => {
                let mut data = args_sim.clone();
                data.push(FaultType::Glitch(4));
                self.fault_data = self.custom_faults_inner(cycles, low_complexity, remaining_input, data, data_analysis, to_filter, prograss_bar)?;
            },
            "Glitch5" => {
                let mut data = args_sim.clone();
                data.push(FaultType::Glitch(5));
                self.fault_data = self.custom_faults_inner(cycles, low_complexity, remaining_input, data, data_analysis, to_filter, prograss_bar)?;
            },
            "Glitch6" => {
                let mut data = args_sim.clone();
                data.push(FaultType::Glitch(6));
                self.fault_data = self.custom_faults_inner(cycles, low_complexity, remaining_input, data, data_analysis, to_filter, prograss_bar)?;
            },
            "Glitch7" => {
                let mut data = args_sim.clone();
                data.push(FaultType::Glitch(7));
                self.fault_data = self.custom_faults_inner(cycles, low_complexity, remaining_input, data, data_analysis, to_filter, prograss_bar)?;
            },
            "Glitch8" => {
                let mut data = args_sim.clone();
                data.push(FaultType::Glitch(9));
                self.fault_data = self.custom_faults_inner(cycles, low_complexity, remaining_input, data, data_analysis, to_filter, prograss_bar)?;
            },
            "Glitch9" => {
                let mut data = args_sim.clone();
                data.push(FaultType::Glitch(9));
                self.fault_data = self.custom_faults_inner(cycles, low_complexity, remaining_input, data, data_analysis, to_filter, prograss_bar)?;
            },
            "Glitch10" => {
                let mut data = args_sim.clone();
                data.push(FaultType::Glitch(10));
                self.fault_data = self.custom_faults_inner(cycles, low_complexity, remaining_input, data, data_analysis, to_filter, prograss_bar)?;
            },
            "BitflipZ" => {
                let mut data = args_sim.clone();
                data.push(FaultType::BitFlip(FlagsCPSR::Z));
                self.fault_data = self.custom_faults_inner(cycles, low_complexity, remaining_input, data, data_analysis, to_filter, prograss_bar)?;
            }
            _ => return Err("Invalid Fault Type".to_string()),
        }

        Ok(self.fault_data.clone())
    }

    pub fn fault_simulation(
        &mut self,
        cycles: usize,
        faults: &[FaultType],
        deep_analysis: bool,
        to_filter: FilterValue,
        prograss_bar: bool,
    ) -> Result<Vec<Vec<FaultData>>, String> {
        //
        println!("Running simulation for faults: {faults:?}");

        // Check if faults are empty
        if faults.is_empty() {
            return Ok(Vec::new());
        }

        // Run simulation to record normal fault program flow as a base for fault injection
        let all_records = trace_run(
            &self.file_data,
            cycles,
            RunType::RecordTrace,
            deep_analysis,
            &[],
        )?;
        debug!("Number of trace steps: {}", all_records.len());
        let mut bar: Option<ProgressBar> = None;
        // Setup progress bar and channel for fault data
        if prograss_bar {
            bar = Some(ProgressBar::new(all_records.len() as u64));
        }
        let (sender, receiver) = channel();

        // Split faults into first and remaining faults
        let (&first_fault, remaining_faults) = faults.split_first().unwrap();

        let (prob_table, mean) = Self::create_prob_table();

        let records = Self::filter_trace(all_records, prob_table, mean, 1 + remaining_faults.len(), to_filter);
        
        // Run main fault simulation loop
        let temp_file_data = &self.file_data;
        let n_result: Result<usize, String> = records
            .into_par_iter()
            .map_with(sender, |s, record| -> Result<usize, String> {
                if let Some(bar) = &bar {
                    bar.inc(1);
                }
                

                let number;
                // Get index of the record
                if let TraceRecord::Instruction { index, .. } = record {
                    // Create a simulation fault record list with the first fault in the list
                    let simulation_fault_records = vec![SimulationFaultRecord {
                        index,
                        fault_type: first_fault,
                    }];

                    // Call recursive fault simulation with first simulation fault record
                    number = Self::fault_simulation_inner(
                        temp_file_data,
                        cycles,
                        remaining_faults,
                        &simulation_fault_records,
                        deep_analysis,
                        to_filter,
                        s,
                    )?;
                    
                } else {
                    return Err("No instruction record found".to_string());
                }

                Ok(number)
            })
            .sum();

        if let Some(bar) = bar {
            bar.finish_and_clear();
        }

        // Sum up successful attacks
        let n = n_result?;
        self.failed = n;
        self.count_sum += n;

        // Return collected successful attacks to caller
        let data: Vec<_> = receiver.iter().collect();
        println!("-> {} attacks executed, {} successful", n, data.len());
        if data.is_empty() {
            Ok(Vec::new())
        } else {
            Ok(data)
        }
    }

    fn fault_simulation_inner(
        file_data: &ElfFile,
        cycles: usize,
        faults: &[FaultType],
        simulation_fault_records: &[SimulationFaultRecord],
        deep_analysis: bool,
        to_filter: FilterValue,
        s: &mut Sender<Vec<FaultData>>,
    ) -> Result<usize, String> {
        let mut n = 0;

        // Check if there are no remaining faults left
        if faults.is_empty() {
            // Run fault simulation. This is the end of the recursion
            simulation_run(file_data, cycles, simulation_fault_records, s)?;
            n += 1;
        } else {
            // Collect trace records with simulation fault records to get new running length (time)
            let all_records = trace_run(
                file_data,
                cycles,
                RunType::RecordTrace,
                deep_analysis,
                simulation_fault_records,
            )?;
            
            // Split faults into first and remaining faults
            let (&first_fault, remaining_faults) = faults.split_first().unwrap();
            
            let (prob_table, mean) = Self::create_prob_table();

            let records = Self::filter_trace(all_records, prob_table, mean, simulation_fault_records.len() +  1 + remaining_faults.len(), to_filter);

            // Iterate over trace records
            for record in records {

                // Get index of the record
                if let TraceRecord::Instruction { index, .. } = record {
                    // Create a copy of the simulation fault records
                    let mut index_simulation_fault_records = simulation_fault_records.to_vec();
                    // Add the created simulation fault record to the list of simulation fault records
                    index_simulation_fault_records.push(SimulationFaultRecord {
                        index,
                        fault_type: first_fault,
                    });

                    // Call recursive fault simulation with remaining faults
                    n += Self::fault_simulation_inner(
                        file_data,
                        cycles,
                        remaining_faults,
                        &index_simulation_fault_records,
                        deep_analysis,
                        to_filter,
                        s,
                    )?;
                }
            }
        }

        Ok(n)
    }

    fn filter_trace(records: Vec<TraceRecord>, prob_table: HashMap<String, f64>, mean: f64, k: usize, to_filter: FilterValue) -> Vec<TraceRecord> {
        if to_filter.0 == 1.0 {
            return records;
        }
        if to_filter.0 == 0.0 {
            return Vec::new();
        }

        let mut filtered_records: Vec<TraceRecord> = records
            .iter()
            .filter_map(|trace| {
                if let TraceRecord::Instruction { .. } = trace {
                    Some(trace.clone())
                } else {
                    None
                }
            })
            .collect();

        match to_filter.1 {
            1 => {
                return Self::filter_1(&mut filtered_records, prob_table, mean, k, to_filter.0);
            },
            2 => {
                return Self::filter_2(filtered_records, prob_table, mean , k,  to_filter.0);
            }
            _ => {
                return Vec::new();
            },
        }
    }

    fn filter_1(records: &mut Vec<TraceRecord>, prob_table: HashMap<String, f64>, mean: f64, k: usize, x: f64) -> Vec<TraceRecord> {
        let cs = Disassembly::new();
        
        
        let n = records.len();
        let size = (f64::powf(x, 1.0 / k as f64) * (n as f64)).ceil() as usize;

        records.sort_by(|a, b| {
            let prob_a = prob_table.get(&cs.get_instr(a)).unwrap_or(&mean);
            let prob_b = prob_table.get(&cs.get_instr(b)).unwrap_or(&mean);
            prob_b.partial_cmp(prob_a).unwrap_or(std::cmp::Ordering::Equal)
        });
        
        return records[..size].to_vec();
    }

    fn filter_2(records: Vec<TraceRecord>, prob_table: HashMap<String, f64>, mean: f64, k: usize, x: f64) -> Vec<TraceRecord> {
        let cs = Disassembly::new();

        // Calculate E(X_i)
        let mut occurrence_map = HashMap::new();
        for record in &records {
            if let TraceRecord::Instruction { .. } = record {
                let instr = cs.get_instr(record);
                *occurrence_map.entry(instr).or_insert(0) += 1;
            }
        }

        let e_x: f64 = occurrence_map.iter().map(|(instr, &count)| {
            let prob = prob_table.get(instr).unwrap_or(&mean);
            prob * count as f64
        }).sum();

        let n_i = records.len() as f64;
        let t = (x.powf(1.0 / k as f64) * n_i) / e_x;

        let mut adjusted_probs: HashMap<String, f64> = occurrence_map.iter().map(|(instr, _)| {
            let prob = prob_table.get(instr).unwrap_or(&mean);
            let adjusted_prob = t * prob;
            (instr.clone(), adjusted_prob)
        }).collect();

        let mut i_1: HashMap<String, usize> = HashMap::new();
        let mut i_0: HashMap<String, usize> = HashMap::new();

        for (instr, &count) in &occurrence_map {
            let adjusted_prob = adjusted_probs.get(instr).unwrap();
            if *adjusted_prob > 1.0 {
                i_1.insert(instr.clone(), count);
            } else {
                i_0.insert(instr.clone(), count);
            }
        }

        while !i_1.is_empty() {
            let o_i: f64 = i_1.iter().map(|(instr, &count)| {
                (adjusted_probs[instr] - 1.0) * count as f64
            }).sum();

            i_1.iter().for_each(|(instr, _)| {
                adjusted_probs.insert(instr.clone(), 1.0);
            });

            let total_i_0: f64 = i_0.iter().map(|(_, &count)| count as f64).sum();

            for (instr, _) in &i_0 {
                let adjusted_prob = adjusted_probs.get_mut(instr).unwrap();
                *adjusted_prob += o_i / total_i_0;
            }

            let mut new_i_1 = HashMap::new();
            let mut new_i_0 = HashMap::new();

            for (instr, &count) in &i_0 {
                let adjusted_prob = adjusted_probs.get(instr).unwrap();
                if *adjusted_prob > 1.0 {
                    new_i_1.insert(instr.clone(), count);
                } else {
                    new_i_0.insert(instr.clone(), count);
                }
            }

            i_1 = new_i_1;
            i_0 = new_i_0;
        }

        let mut rng = rand::thread_rng();
        let filtered_records: Vec<TraceRecord> = records.into_iter().filter(|record| {
            if let TraceRecord::Instruction { .. } = record {
                let instr = cs.get_instr(record);
                let prob = adjusted_probs.get(&instr).cloned().unwrap_or(0.0);
                rng.gen::<f64>() < prob
            } else {
                false
            }
        }).collect();

        filtered_records
    }
    
    fn create_prob_table() -> (HashMap<String, f64>, f64) {
        let mut prob_table = HashMap::new();

        prob_table.insert("str".to_string(), 0.8185823543);
        prob_table.insert("cmp".to_string(), 0.4876647557);
        prob_table.insert("movs".to_string(), 0.4396788568);
        prob_table.insert("bl".to_string(), 0.2639400649);
        prob_table.insert("stm.w".to_string(), 0.1948807069);
        prob_table.insert("eors".to_string(), 0.1441131428);
        prob_table.insert("ldm.w".to_string(), 0.1202486834);
        prob_table.insert("beq".to_string(), 0.1140286320);
        prob_table.insert("push".to_string(), 0.1012555396);
        prob_table.insert("ldr".to_string(), 0.0967017150);
        prob_table.insert("add".to_string(), 0.0896197561);
        prob_table.insert("mov".to_string(), 0.0861948956);
        prob_table.insert("add.w".to_string(), 0.0725542911);
        prob_table.insert("pop".to_string(), 0.0594311249);
        prob_table.insert("stm".to_string(), 0.0306264501);
        prob_table.insert("bx".to_string(), 0.0166666667);
        prob_table.insert("strd".to_string(), 0.0000000000);
        prob_table.insert("sub".to_string(), 0.0000000000);

        // prob_table.insert("b".to_string(), 58.398 / 100.0);
        // prob_table.insert("adds".to_string(), 29.618 / 100.0);
        // prob_table.insert("movs".to_string(), 26.906 / 100.0);
        // prob_table.insert("bne".to_string(), 23.093 / 100.0);
        // prob_table.insert("pop".to_string(), 15.611 / 100.0);
        // prob_table.insert("cmp".to_string(), 15.285 / 100.0);
        // prob_table.insert("bl".to_string(), 10.821 / 100.0);
        // prob_table.insert("str".to_string(), 10.809 / 100.0);
        // prob_table.insert("ldr".to_string(), 9.309 / 100.0);
        // prob_table.insert("beq".to_string(), 8.572 / 100.0);
        // prob_table.insert("cbz".to_string(), 5.884 / 100.0);
        // prob_table.insert("mov".to_string(), 5.215 / 100.0);
        // prob_table.insert("ldm.w".to_string(), 5.0 / 100.0);
        // prob_table.insert("stm.w".to_string(), 5.0 / 100.0);
        // prob_table.insert("add".to_string(), 4.978 / 100.0);
        // prob_table.insert("ldrb".to_string(), 2.632 / 100.0);
        // prob_table.insert("push".to_string(), 0.202 / 100.0);
        // prob_table.insert("bx".to_string(), 0.0);
        // prob_table.insert("add.w".to_string(), 0.0);
        // prob_table.insert("eors".to_string(), 0.0);
        // prob_table.insert("blo".to_string(), 0.0);
        // prob_table.insert("mov.w".to_string(), 0.0);
        // prob_table.insert("stm".to_string(), 0.0);
        // prob_table.insert("strd".to_string(), 0.0);
        // prob_table.insert("sub".to_string(), 0.0);

            // for prob in prob_table.values_mut() {
            //     *prob = 0.1;
            // }

        let mut prob = 0.0;
        let mut count = 0.0;
        for (_, p) in prob_table.clone() {
            prob += p;
            count += 1.0;
        }
        let mean = prob / count;

        (prob_table, mean)
    }
}

/// Run the simulation with faults and return a trace of the program flow
///
/// If the simulation fails, return an empty vector
///
fn trace_run(
    file_data: &ElfFile,
    cycles: usize,
    run_type: RunType,
    deep_analysis: bool,
    records: &[SimulationFaultRecord],
) -> Result<Vec<TraceRecord>, String> {
    let mut simulation = Control::new(file_data);
    let data = simulation.run_with_faults(cycles, run_type, deep_analysis, records)?;
    match data {
        Data::Trace(trace) => Ok(trace),
        _ => Ok(Vec::new()),
    }
}

fn simulation_run(
    file_data: &ElfFile,
    cycles: usize,
    records: &[SimulationFaultRecord],
    s: &mut Sender<Vec<FaultData>>,
) -> Result<(), String> {
    let mut simulation = Control::new(file_data);
    let data = simulation.run_with_faults(cycles, RunType::Run, false, records)?;
    if let Data::Fault(fault) = data {
        if !fault.is_empty() {
            s.send(fault).unwrap();
        }
    }

    Ok(())
}
