
from dataclasses import dataclass
from math import isfinite

DT = 0.020  # simulated plant/control sample interval (20 ms)
V_LIMIT = 12.0
KP = 0.18
KI = 0.60


@dataclass
class Motor:
    current: float = 0.0
    omega: float = 0.0
    R: float = 2.0       # Ohm
    L: float = 0.02      # H
    Kt: float = 0.1      # N*m / A
    Ke: float = 0.1      # V*s / rad
    J: float = 0.002     # kg*m^2
    b: float = 0.001     # N*m*s / rad

    def derivative(self, state, voltage: float, load: float):
        current, speed = state
        di = (voltage - self.R * current - self.Ke * speed) / self.L
        dw = (self.Kt * current - self.b * speed - load) / self.J
        return (di, dw)

    def step(self, voltage: float, dt: float = DT, load: float = 0.0):
        """Runge-Kutta 4th order integration; ten 2-ms substeps."""
        assert isfinite(voltage) and abs(voltage) <= V_LIMIT + 1e-6
        h = dt / 10.0
        current, omega = self.current, self.omega
        for _ in range(10):
            k1 = self.derivative((current, omega), voltage, load)
            k2 = self.derivative((current + .5*h*k1[0], omega + .5*h*k1[1]), voltage, load)
            k3 = self.derivative((current + .5*h*k2[0], omega + .5*h*k2[1]), voltage, load)
            k4 = self.derivative((current + h*k3[0], omega + h*k3[1]), voltage, load)
            current += h * (k1[0] + 2*k2[0] + 2*k3[0] + k4[0]) / 6
            omega += h * (k1[1] + 2*k2[1] + 2*k3[1] + k4[1]) / 6
        self.current, self.omega = current, omega
        return self.omega


class DemoPI:
    def __init__(self):
        self.integral = 0.0

    def update(self, reference, measured):
        error = reference - measured
        candidate = self.integral + KI * DT * error
        u_unsat = KP * error + candidate
        if (-V_LIMIT <= u_unsat <= V_LIMIT or
                (u_unsat > V_LIMIT and error < 0) or
                (u_unsat < -V_LIMIT and error > 0)):
            self.integral = candidate
        return max(-V_LIMIT, min(V_LIMIT, KP * error + self.integral))


def reference_at(t: float) -> float:
    return 80.0 if t < 5.0 - 1e-9 else 60.0


def disturbance_at(t: float) -> float:
    return 0.0 if t < 3.5 - 1e-9 else 0.010
