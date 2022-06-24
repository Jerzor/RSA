import argparse
import math
import string
import cv2
import numpy as np
import numpy as np
import hashlib
import os
import io

from collections import namedtuple
from pyparsing import nums
from scipy.stats import entropy

from scipy import stats as stats
from Cryptodome.PublicKey import RSA  
from Cryptodome.Cipher import PKCS1_OAEP



FrameSize = namedtuple('FrameSize', ['width', 'height'])
FaultBoundary = namedtuple('FaultBoundary', ['lower', 'upper'])


def bit_list_to_bit_string(bit_list: list[int]) -> str:
    bit_string = ''.join([str(x & 1) for x in bit_list])
    return bit_string


def split_bit_string_to_n_bit_nums(n: int, bit_string: str) -> list[int]:
    n_bit_nums = [int(bit_string[i:i + n], 2) for i in range(0, len(bit_string), n)]
    return n_bit_nums


def calc_entropy(nums: list[int]) -> float:
    p, _ = np.histogram(nums, bins=256, range=(0, 255), density=True)
    entropy_val = entropy(p, base=2)
    return entropy_val

    
def isTrueCode(message: string, code: string):
    if(message == code):
        return True
    return False


class Camera:
    def __init__(self, src: int, frame_size: FrameSize, fps: int, no_frames_auto_settings: int) -> None:
        self.src: int = src
        self.frame_size: FrameSize = frame_size
        self.fps: int = fps
        self.no_frames_auto_settings: int = no_frames_auto_settings
        self.cap = cv2.VideoCapture("o1.avi")

        if not self.cap.isOpened():
            raise Exception("Couldn't open a video capture")

        self.cap.set(cv2.CAP_PROP_FRAME_WIDTH, frame_size.width)
        self.cap.set(cv2.CAP_PROP_FRAME_HEIGHT, frame_size.height)
        self.cap.set(cv2.CAP_PROP_FPS, fps)

    def take_frames(self, n: int) -> list:
        frames = []

        for i in range(self.no_frames_auto_settings + n):
            ret, frame = self.cap.read()
            if not ret:
                raise Exception("Didn't receive frame")
            frames.append(frame)

        return frames[-n:]

    def release_cap(self) -> None:
        self.cap.release()



class Generator:
    def __init__(self, fault_boundary: FaultBoundary, expected_no_bits: int, extra_frames: int = 3) -> None:
        self.fault_boundary: FaultBoundary = fault_boundary
        self.expected_no_bits: int = expected_no_bits
        self.extra_frames: int = extra_frames

        expected_no_bits_sqrt: int = math.ceil(math.sqrt(expected_no_bits))
        self.cols: int = expected_no_bits_sqrt
        self.rows: int = expected_no_bits_sqrt

        self.matrix: list[list[int]] = [[0 for j in range(self.cols)] for i in range(self.rows)]
        self.matrix_length: int = self.cols * self.rows

        self.current_length: int = 0

        self.row: int = 0
        self.col: int = 0

    def fill_matrix(self, frames) -> None:
        if self.current_length == self.matrix_length:
            raise Exception('Matrix is already filled')

        for i, frame in enumerate(frames):
            frame = np.ravel(frame)
            filtered_frame = filter(
                lambda x: self.fault_boundary.lower <= x <= self.fault_boundary.upper,
                frame
            )

            for val in filtered_frame:
                if self.col == self.cols:
                    self.col = 0
                    self.row += 1
                if self.row >= self.rows:
                    break

                self.matrix[self.row][self.col] = (val + 1) & 1 if i & 1 else val & 1
                    
                self.current_length += 1
                self.col += 1

    def get_hashed_matrix(self) -> list[int]:
        if self.current_length < self.matrix_length:
            raise Exception('Matrix shall be filled')

        hashed_result = np.ravel(self.matrix, 'F')
        return hashed_result[:self.expected_no_bits]

    def needed_no_frames(self, frame_size: FrameSize) -> int:
        no_frames: int = math.ceil(self.matrix_length / (frame_size.width * frame_size.height))
        no_frames += self.extra_frames
        return no_frames

    def is_matrix_filled(self) -> bool:
        return self.current_length == self.matrix_length


if __name__ == '__main__':
    def gen_8bit_nums(expected_no_nums: int, of_path: str):


        frame_size = FrameSize(width=1280, height=720)
        fault_boundary = FaultBoundary(lower=2, upper=253)
        camera = Camera(src=0, frame_size=frame_size, fps=30, no_frames_auto_settings=120)
        expected_no_bits = expected_no_nums * 8
        generator = Generator(fault_boundary=fault_boundary, expected_no_bits=expected_no_bits)
        needed_no_frames = generator.needed_no_frames(frame_size)

        frames = camera.take_frames(needed_no_frames)

        camera.release_cap()

        generator.fill_matrix(frames)

        random_bits = generator.get_hashed_matrix()

        random_bits_string = bit_list_to_bit_string(random_bits)

        nums_8bit = split_bit_string_to_n_bit_nums(8, random_bits_string)

        # with open(of_path, 'w') as f:
        #     for num in nums_8bit:
        #         f.write(f'{num}\n')

# =====================================================================================  
# =====================================    RSA    =====================================
# =====================================================================================   

        with open('./__pycache__/test.txt', 'wb') as f:
            np.save(f, nums_8bit)

        with open('./__pycache__/test.txt', 'rb') as f:   
           key = RSA.generate(1024,f.read)

        public_key = key.publickey()

        # klucze
        public_key_to_show = int(str(public_key)[18:31], 16)
        private_key_to_show = int(str(key)[19:32], 16)
        print('\nKlucz publiczny: ', public_key_to_show)
        print('Klucz prywatny: ', private_key_to_show, "\n\n")

        # przyjmowanie wiadomosci
        inputA = input("Wiadomość A: ")
        print("\nWiadomość A: ", inputA)
 
        # haszowanie wiadomosci
        hash_object = hashlib.sha256(str.encode(inputA))
        hex_dig = hash_object.hexdigest()
        print('Zahashowana wiadomośc A: ', hex_dig, "\n")

        # kodowanie wiadomosci kluczem publicznym
        encryptor = PKCS1_OAEP.new(public_key)
        encrypted = encryptor.encrypt(str.encode(hex_dig))

        # odkodowanie wiadomosci kluczem prywatnym
        decryptor = PKCS1_OAEP.new(key)
        decrypted = decryptor.decrypt(encrypted)
        decrypted = decrypted.decode("utf-8")

        print("Wiadomość otrzymana: ", decrypted)

        # porównywanie nowej zhaszowanej wiadomosci z odszyfrowaną
        if(isTrueCode(hex_dig, decrypted)):
            print("Wiadomości się zgadzają. \n\n")
        else:
            print("Wiadomości się nie zgadzają. \n\n")


        # nowa wiadomosć B w celu sprawdzenia poprawności zaszyfrowanej wiadomosci
        inputB = input("Nowa wiadomość B: ")
        print("Nowa wiadomość B: ", inputB)

        # haszowanie nowej wiadomosci
        hash_object2 = hashlib.sha256(str.encode(inputB))
        hex_dig2 = hash_object2.hexdigest()
        print('HASH #B: ',hex_dig2, "\n")

        # porownanie nowej zhashowanej wiadomosci z odebraną poprzenią
        if(isTrueCode(hex_dig2, decrypted)):
            print("Wiadomości się zgadzają. \n\n")
        else:
            print("Wiadomości się nie zgadzają. \n\n")
         
# =====================================================================================  


    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument('-n', '--no-nums', action='store', type=int, help='No. 8-bit nums to generate')
    arg_parser.add_argument('-o', '--output', action='store', type=str, help='Output file path')
    args = arg_parser.parse_args()

    if not args.no_nums:
        print('No. 8-bit nums must be specified')
        exit(1)
    if not args.output:
        print('Output file path must be specified')
        exit(1)

    try:
        gen_8bit_nums(expected_no_nums=args.no_nums, of_path=args.output)
        exit(0)
    except KeyboardInterrupt:
        pass
    except Exception as e:
        print(e)
        exit(1)
