use clap::{Arg, Command};
use std::fs::File;
use std::io::{self, Cursor, Read, Write};
use std::path::Path;
use image::{DynamicImage, GenericImageView, ImageBuffer};
use reqwest::blocking::get;
use windows::Win32::UI::Shell::ExtractIconW;
use std::convert::TryInto;

fn read_file_to_bytes(filepath: &Path) -> Result<Vec<u8>, io::Error> {
    let mut file = File::open(filepath)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;
    Ok(buffer)
}

fn write_bytes_to_file(filepath: &Path, data: &[u8]) -> Result<(), io::Error> {
    let mut file = File::create(filepath)?;
    file.write_all(data)?;
    Ok(())
}

fn embed_data_in_image(image: &DynamicImage, data: &[u8]) -> Result<DynamicImage, String> {
    let mut img = image.to_rgba8();
    let (width, height) = img.dimensions();
    let total_bits_needed = (data.len() + 4) * 8; // 8 bits per byte + 4 bytes for length metadata
    let total_pixels_needed = total_bits_needed; // 1 bit per pixel

    if (width as usize) * (height as usize) < total_pixels_needed {
        return Err(format!(
            "Image is too small to hold the data. Required: {} pixels, Available: {} pixels",
            total_pixels_needed,
            width * height
        ));
    }

    let mut bit_index = 0;

    println!("Embedding data into image...");

    // Prepend the length of the data as 4 bytes (32-bit unsigned integer)
    let data_length = data.len() as u32;
    let length_bytes = data_length.to_be_bytes(); // Big-endian for consistency

    // Combine length bytes and data bytes
    let combined_data: Vec<u8> = length_bytes.iter().chain(data.iter()).cloned().collect();

    // Process combined data bits
    for byte in combined_data.iter() {
        for bit in 0..8 {
            let pixel_index = bit_index / 4;
            let color_channel = (bit_index % 4) as usize; // 0: R, 1: G, 2: B, 3: A
            let current_pixel = img.get_pixel_mut((pixel_index % width) as u32, (pixel_index / width) as u32);
            let mask = 1 << (7 - bit);
            let data_bit = (byte & mask) >> (7 - bit);
            current_pixel.0[color_channel] = (current_pixel.0[color_channel] & !1) | data_bit;
            bit_index += 1;
        }
    }

    println!("Data embedded into image.");
    Ok(DynamicImage::ImageRgba8(img))
}

fn extract_data_from_image(image: &DynamicImage) -> Result<Vec<u8>, String> {
    println!("Extracting data from image...");
    let img = image.to_rgba8();
    let (width, height) = img.dimensions();

    let mut bit_index = 0;
    let mut length_bits = vec![0u8; 32]; // First, extract 32 bits (4 bytes) for the length

    // Extract the length (first 4 bytes)
    for i in 0..32 {
        let pixel_index = bit_index / 4;
        let color_channel = bit_index % 4; // 0: R, 1: G, 2: B, 3: A
        let pixel = img.get_pixel((pixel_index % width) as u32, (pixel_index / width) as u32);
        length_bits[i] = (pixel.0[color_channel as usize] & 1) as u8;
        bit_index += 1;
    }

    // Convert length bits to a u32
    let data_length = bits_to_bytes(length_bits)[0..4]
        .try_into()
        .map(|b: [u8; 4]| u32::from_be_bytes(b))
        .map_err(|_| "Failed to parse data length".to_string())?;

    let total_bits_needed = (data_length as usize) * 8; // 8 bits per byte

    if (bit_index as usize) + total_bits_needed > (width as usize) * (height as usize) {
        return Err("Image is too small to contain the requested data".to_string());
    }

    let mut data_bits = vec![0u8; total_bits_needed];

    // Extract bits for the data
    for i in 0..total_bits_needed {
        let pixel_index = bit_index / 4;
        let color_channel = bit_index % 4; // 0: R, 1: G, 2: B, 3: A
        let pixel = img.get_pixel((pixel_index % width) as u32, (pixel_index / width) as u32);
        data_bits[i] = (pixel.0[color_channel as usize] & 1) as u8;
        bit_index += 1;
    }

    // Convert bits to bytes
    let extracted_data = bits_to_bytes(data_bits);
    println!("Data extracted from image.");
    Ok(extracted_data)
}

fn bits_to_bytes(bits: Vec<u8>) -> Vec<u8> {
    bits.chunks(8)
        .map(|chunk| {
            chunk
                .iter()
                .enumerate()
                .fold(0, |acc, (i, &bit)| acc | ((bit as u8) << (7 - i)))
        })
        .collect()
}

fn main() {
    let matches = Command::new("Image LSB Encoder/Decoder")
        .version("1.0")
        .about("Embeds and extracts data using LSB steganography in images")
        .arg(
            Arg::new("operation")
                .short('o')
                .long("operation")
                .value_parser(["encode", "decode"])
                .required(true)
                .help("Operation to perform: encode or decode"),
        )
        .arg(
            Arg::new("input")
                .short('i')
                .long("input")
                .value_name("INPUT")
                .required(true)
                .help("Path to input image file"),
        )
        .arg(
            Arg::new("data")
                .short('d')
                .long("data")
                .value_name("DATA")
                .required_if_eq("operation", "encode")
                .help("Path to file containing data to embed (required for encode)"),
        )
        .arg(
            Arg::new("output")
                .short('f')
                .long("output")
                .value_name("OUTPUT")
                .required(true)
                .help("Path to output file"),
        )
        .get_matches();

    let operation = matches.get_one::<String>("operation").unwrap();
    let input_path = matches.get_one::<String>("input").unwrap();
    let output_path = matches.get_one::<String>("output").unwrap();

    if operation == "encode" {
        let data_path = matches.get_one::<String>("data").unwrap();
        let input_image = image::open(input_path).expect("Failed to open input image");
        let secret_data = read_file_to_bytes(Path::new(data_path)).expect("Failed to read secret data file");

        match embed_data_in_image(&input_image, &secret_data) {
            Ok(encoded_image) => {
                encoded_image.save(output_path).expect("Failed to save encoded image");
                println!("Data successfully embedded and saved to {}", output_path);
            }
            Err(e) => eprintln!("Error embedding data: {}", e),
        }
    } else if operation == "decode" {
        let input_image = image::open(input_path).expect("Failed to open input image");

        match extract_data_from_image(&input_image) {
            Ok(extracted_data) => {
                write_bytes_to_file(Path::new(output_path), &extracted_data)
                    .expect("Failed to write extracted data to file");
                println!("Data successfully extracted and saved to {}", output_path);
            }
            Err(e) => eprintln!("Error extracting data: {}", e),
        }
    }
}
