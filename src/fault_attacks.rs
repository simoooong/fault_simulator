use crate::disassembly::Disassembly;
pub use crate::simulation::FaultType;
pub use crate::simulation::FlagsCPSR;
pub use crate::simulation::FaultData;
use crate::simulation::*;

use addr2line::gimli;

use rayon::prelude::*;
use strum::IntoEnumIterator;

use std::sync::mpsc::{channel, Sender};

use indicatif::ProgressBar;

use itertools::Itertools;

use log::debug;

pub struct FaultAttacks {
    cs: Disassembly,
    pub file_data: ElfFile,
    fault_data: Vec<Vec<FaultData>>,
    pub count_sum: usize,
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
                false,
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
        low_complexity: bool,
        range: std::ops::RangeInclusive<usize>,
    ) -> Result<(bool, usize), String> {
        // Run cached single nop simulation
        for i in range {
            self.fault_data =
                self.fault_simulation(cycles, &[FaultType::Glitch(i)], low_complexity)?;

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
        low_complexity: bool,
        range: std::ops::RangeInclusive<usize>,
    ) -> Result<(bool, usize), String> {
        // Run cached double nop simulation
        let it = range.clone().cartesian_product(range);
        for t in it {
            self.fault_data = self.fault_simulation(
                cycles,
                &[FaultType::Glitch(t.0), FaultType::Glitch(t.1)],
                low_complexity,
            )?;

            if !self.fault_data.is_empty() {
                break;
            }
        }

        Ok((!self.fault_data.is_empty(), self.count_sum))
    }

    pub fn single_bit_flip(
        &mut self,
        cycles: usize,
        low_complexity: bool
    ) -> Result<(bool, usize), String> {
        for flg in FlagsCPSR::iter() {
            self.fault_data =
                self.fault_simulation(cycles, &[FaultType::BitFlip(flg)], low_complexity)?;
        }

        Ok((!self.fault_data.is_empty(), self.count_sum))
    }

    pub fn custom_faults(
        &mut self,
        cycles: usize,
        low_complexity: bool,
        args_input: &[String],
    ) -> Result<(bool, usize), String> {
        let args_sim: Vec<FaultType> = Vec::new();

        self.fault_data = self.custom_faults_inner(cycles, low_complexity, args_input, args_sim)?;

        Ok((!self.fault_data.is_empty(), self.count_sum))
    }

    fn custom_faults_inner(
        &mut self,
        cycles: usize,
        low_complexity: bool,
        args_input: &[String],
        args_sim: Vec<FaultType>
    ) -> Result<Vec<Vec<FaultData>>, String> {
        if args_input.is_empty() {
            self.fault_data =
                self.fault_simulation(cycles, &args_sim, low_complexity)?;

            return Ok(self.fault_data.clone());
        }
        
        let (&ref fault, remaining_input) = args_input.split_first().unwrap();
    
        match fault.as_str() {
            "Glitch" => {
                for i in 1..10 {
                    let mut data = args_sim.clone();
                    data.push(FaultType::Glitch(i));
                    self.fault_data = self.custom_faults_inner(cycles, low_complexity, remaining_input, data)?;
                }
            },
            "Bitflip" => {
                for flg in FlagsCPSR::iter() {
                    let mut data = args_sim.clone();
                    data.push(FaultType::BitFlip(flg));
                    self.fault_data = self.custom_faults_inner(cycles, low_complexity, remaining_input, data)?;
                }
            },
            _ => return Err("Invalid Fault Type".to_string()),
        }

        Ok(self.fault_data.clone())
    }

    pub fn fault_simulation(
        &mut self,
        cycles: usize,
        faults: &[FaultType],
        low_complexity: bool,
    ) -> Result<Vec<Vec<FaultData>>, String> {
        //
        println!("Running simulation for faults: {faults:?}");

        // Check if faults are empty
        if faults.is_empty() {
            return Ok(Vec::new());
        }

        // Run simulation to record normal fault program flow as a base for fault injection
        let records = trace_run(
            &self.file_data,
            cycles,
            RunType::RecordTrace,
            low_complexity,
            &[],
        )?;
        debug!("Number of trace steps: {}", records.len());

        // Setup progress bar and channel for fault data
        let bar = ProgressBar::new(records.len() as u64);
        let (sender, receiver) = channel();

        // Split faults into first and remaining faults
        let (&first_fault, remaining_faults) = faults.split_first().unwrap();

        // Run main fault simulation loop
        let temp_file_data = &self.file_data;
        let n_result: Result<usize, String> = (0..records.len())
            .into_par_iter()
            .map_with(sender, |s, index| -> Result<usize, String> {
                bar.inc(1);

                // Create a simulation fault record list with the first fault in the list
                let simulation_fault_records = vec![SimulationFaultRecord {
                    index,
                    fault_type: first_fault,
                }];

                // Call recursive fault simulation with first simulation fault record
                let number = Self::fault_simulation_inner(
                    temp_file_data,
                    cycles,
                    remaining_faults,
                    &simulation_fault_records,
                    low_complexity,
                    s,
                )?;
                Ok(number)
            })
            .sum();

        bar.finish_and_clear();
        // Sum up successful attacks
        let n = n_result?;
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
        low_complexity: bool,
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
            let records = trace_run(
                file_data,
                cycles,
                RunType::RecordTrace,
                low_complexity,
                simulation_fault_records,
            )?;

            // Split faults into first and remaining faults
            let (&first_fault, remaining_faults) = faults.split_first().unwrap();

            // Iterate over trace record length
            for index in 0..records.len() {
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
                    low_complexity,
                    s,
                )?;
            }
        }

        Ok(n)
    }
}

fn trace_run(
    file_data: &ElfFile,
    cycles: usize,
    run_type: RunType,
    low_complexity: bool,
    records: &[SimulationFaultRecord],
) -> Result<Vec<TraceRecord>, String> {
    let mut simulation = Control::new(file_data);
    let data = simulation.run_with_faults(cycles, run_type, low_complexity, records)?;
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
