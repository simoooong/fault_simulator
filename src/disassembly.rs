use std::fs::File;
use crate::prelude::FaultType;
use crate::simulation::{FaultData, TraceRecord};
use addr2line::{fallible_iterator::FallibleIterator, gimli};
use capstone::prelude::*;
use csv::Writer;
use std::error::Error;
use std::collections::HashMap;

pub struct Disassembly {
    cs: Capstone,
}

impl Disassembly {
    pub fn new() -> Self {
        let cs = Capstone::new()
            .arm()
            .mode(arch::arm::ArchMode::Thumb)
            .extra_mode([arch::arm::ArchExtraMode::MClass].iter().copied())
            .detail(true)
            .build()
            .expect("Failed to create Capstone object");

        Self { cs }
    }

    fn disassembly_fault_data(
        &self,
        fault_data: &FaultData,
        debug_context: &addr2line::Context<
            gimli::EndianReader<gimli::RunTimeEndian, std::rc::Rc<[u8]>>,
        >,
    ) {
        let insns_data = self
            .cs
            .disasm_all(
                &fault_data.original_instructions,
                fault_data.record.address(),
            )
            .expect("Failed to disassemble");

        for i in 0..insns_data.as_ref().len() {
            let ins = &insns_data.as_ref()[i];
            println!(
                "0x{:X}:  {} {} -> {:?}",
                ins.address(),
                ins.mnemonic().unwrap(),
                ins.op_str().unwrap(),
                fault_data.fault.fault_type
            );
            self.print_debug_info(ins.address(), debug_context);
        }
    }

    
    fn disassembly_write_fault_data(
        &self,
        fault_data: &FaultData,
    ) -> HashMap<String, usize> {
        let mut mnemonic_counts: HashMap<String, usize> = HashMap::new();
    
        let insns_data = self
            .cs
            .disasm_all(
                &fault_data.original_instructions,
                fault_data.record.address(),
            )
            .expect("Failed to disassemble");
    
        for ins in insns_data.iter() {
            let mnemonic = ins.mnemonic().unwrap_or_default().to_string();
            let count = mnemonic_counts.entry(mnemonic.clone()).or_insert(0);
            *count += 1;
        }
    
        mnemonic_counts
    }


    /// Print trace_record of given trace_records vector
    pub fn disassembly_trace_records(&self, trace_records: &Option<Vec<TraceRecord>>) {
        let mut pre_registers: Option<[u32; 17]> = None;

        if let Some(trace_records) = trace_records {
            trace_records
                .iter()
                .for_each(|trace_record| match trace_record {
                    TraceRecord::Instruction {
                        address,
                        index: _,
                        asm_instruction,
                        registers,
                    } => {
                        let insns_data = self
                            .cs
                            .disasm_all(asm_instruction, *address)
                            .expect("Failed to disassemble");

                        for i in 0..insns_data.as_ref().len() {
                            let ins = &insns_data.as_ref()[i];

                            print!(
                                "0x{:X}:  {:6} {:40}     < ",
                                ins.address(),
                                ins.mnemonic().unwrap(),
                                ins.op_str().unwrap(),
                            );
                            if let Some(registers) = registers {
                                // Allways print CPU flags
                                let cpsr = registers[16];
                                let flag_n = (cpsr & 0x80000000) >> 31;
                                let flag_z = (cpsr & 0x40000000) >> 30;
                                let flag_c = (cpsr & 0x20000000) >> 29;
                                let flag_v = (cpsr & 0x10000000) >> 28;
                                print!("NZCV:{}{}{}{} ", flag_n, flag_z, flag_c, flag_v);
                                // Print only changed register values
                                if let Some(pre_registers) = pre_registers {
                                    (0..15).for_each(|index| {
                                        if pre_registers[index] != registers[index] {
                                            print!("R{}=0x{:08X} ", index, registers[index]);
                                        }
                                    });
                                }
                            }
                            println!(">");
                            // Remember register state
                            pre_registers = *registers;
                        }
                    }
                    TraceRecord::Fault {
                        address: _,
                        fault_type,
                    } => {
                        println!("{:?}", fault_type)
                    }
                });
            println!("------------------------");
        }
    }

    pub fn write_instruction_information(
        &self,
        trace_records: Vec<TraceRecord>,
        instruction_rel: HashMap<String, f64>,
        len: usize,
        writer: &mut Writer<File>,
    ) -> Result<(), Box<dyn Error>> {
        let mut mnemonic_counts: HashMap<String, usize> = HashMap::new();

        trace_records
                .iter()
                .for_each(|trace_record| match trace_record {
                    TraceRecord::Instruction {
                        address,
                        index: _,
                        asm_instruction,
                        registers: _,
                    } => {
                        let insns_data = self
                            .cs
                            .disasm_all(asm_instruction, *address)
                            .expect("Failed to disassemble");

                            for ins in insns_data.iter() {
                                let mnemonic = ins.mnemonic().unwrap_or_default().to_string();
                                let count = mnemonic_counts.entry(mnemonic.clone()).or_insert(0);
                                *count += 1;
                            }
                    }
                    _ => ()
                });
        
        let instructions_with_counts: Vec<(&String, &usize)> = mnemonic_counts.iter().collect();
        
        let mut writing = Vec::new();
        for (instr,count) in instructions_with_counts {

            let rel = match instruction_rel.get(instr) {
                Some(&value) => value,
                _ => 0.0
            };
            let rel_distribution = rel / ((len as f64) * (*count as f64));

            writing.push((instr, count, rel_distribution));

            
        }
        writing.sort_by(|a,b| a.2.partial_cmp(&b.2).unwrap());
        writing.reverse();

        for (instr, count, rel) in writing {
            let rel_distribution = format!("{:.1$}", rel , 10);

            writer.write_record(&[
                instr.to_string(),
                count.to_string(),
                rel_distribution
            ])?;
        }
        
        Ok(())
    }

    // check if a given trace matches a instrucion
    pub fn check_trace_record(&self, record: TraceRecord, filter: Vec<&str>) -> bool {
        match record {
            TraceRecord::Instruction {
                address,
                index: _,
                asm_instruction,
                registers: _
            } => {
                let insns_data = self
                    .cs
                    .disasm_all(&asm_instruction, address)
                    .expect("Failed to disassemble");

                for i in 0..insns_data.as_ref().len() {
                     let ins = &insns_data.as_ref()[i];
                     return filter.iter().any(|&v| v == ins.mnemonic().unwrap());      
                }
            },
            _ => ()
        }
        return false;
    }

    /// Print fault data of given fault_data_vec vector
    pub fn print_fault_records(
        &self,
        fault_data_vec: &[Vec<FaultData>],
        debug_context: &addr2line::Context<
            gimli::EndianReader<gimli::RunTimeEndian, std::rc::Rc<[u8]>>,
        >,
    ) {
        fault_data_vec
            .iter()
            .enumerate()
            .for_each(|(attack_num, fault_context)| {
                println!("Attack number {}", attack_num + 1);
                fault_context.iter().for_each(|fault_data| {
                    self.disassembly_fault_data(fault_data, debug_context);
                    println!();
                });
                println!("------------------------");
            });
    }

    pub fn write_fault_records(
        &self,
        len: usize,
        fault_data_vec: &[Vec<FaultData>],
        writer: &mut Writer<File>,
        failed_attacks: usize,
        instruction_rel: &mut HashMap<String, f64>,
    ) -> Result<(), Box<dyn Error>> {
        let successful_attacks = fault_data_vec.len();
        let success_rate = format!("{:.1$}", (successful_attacks as f64) / (failed_attacks as f64) * 100.0, 3);
        let mut attack_vectors:Vec<String> = Vec::new();
        let mut instruction_counts: HashMap<String, usize> = HashMap::new();

        fault_data_vec
            .iter()
            .enumerate()
            .for_each(|(attack_num, fault_context)| {
                // println!("Attack number {}", attack_num + 1);
                fault_context.iter().enumerate().for_each(|(pos, fault_data)| {
                    if attack_num == 0 && pos < len {
                        attack_vectors.push(format!("{:?}", fault_data.clone().fault.fault_type));
                    }
                    let targets = self.disassembly_write_fault_data(fault_data);
                    for (instruction, count) in targets {
                        *instruction_counts.entry(instruction.clone()).or_insert(0) += count;

                        let instr_size = match fault_data.fault.fault_type {
                            FaultType::Glitch(i) => i,
                            FaultType::BitFlip(_) => 1,
                        };
                        *instruction_rel.entry(instruction.clone()).or_insert(0.0) += (count as f64) / (instr_size as f64);
                    }
                });
            });

            // Collect the instruction counts into a vector of tuples
            let mut instructions_with_counts: Vec<(&String, &usize)> = instruction_counts.iter().collect();

            // Sort the vector by count in descending order
            instructions_with_counts.sort_by(|a, b| b.1.cmp(a.1));

            // Format the sorted instructions
            let targeted_instructions = instructions_with_counts
                .iter()
                .map(|(instruction, count)| format!("{}: {}", instruction, count))
                .collect::<Vec<String>>();

            writer.write_record(&[
                attack_vectors.join(",").to_string(),
                successful_attacks.to_string(),
                failed_attacks.to_string(),
                success_rate.to_string(),
                targeted_instructions.join(",").to_string(),
            ])?;

        Ok(())
    }

    fn print_debug_info(
        &self,
        address: u64,
        debug_context: &addr2line::Context<
            gimli::EndianReader<gimli::RunTimeEndian, std::rc::Rc<[u8]>>,
        >,
    ) {
        if let Ok(frames) = debug_context.find_frames(address).skip_all_loads() {
            for frame in frames.iterator().flatten() {
                if let Some(location) = frame.location {
                    match (location.file, location.line) {
                        (Some(file), Some(line)) => {
                            println!("\t\t{:?}:{:?}", file, line)
                        }

                        (Some(file), None) => println!("\t\t{:?}", file),
                        _ => println!("No debug info available"),
                    }
                }
            }
        }
    }
}

