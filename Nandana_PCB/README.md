*EXPLANATION OF WORKING OF ELECTRONIC DICE*


The D9 pin is the primary input channel to detect human commands via the push button.

Initially, the D9 pin sits at high voltage. The instant a user presses the button, the switch closes. This immediately pulls the voltage on Pin D9 straight down to 0V ground connection via the connector socket.

Hence, this pressing of the push button is considered as rolling of dice.

The microcontroller uses an internal mathematical sequence to generate a pseudo-random integer restricted strictly between 1 and 6.

Corresponding to a random  number it sends the output signals through specific pins from D2 to D8 so that the appropriate LEDs light up in order to generate the corresponding pattern as in a real dice on this electronic dice.

Hence, according to the decision made by the microcontroller, high voltage is send through specific output pins that make those LEDs light up and the dice work.

That +5V electrical current travels out of the pin, passes through a 200ohm resistor (which safely acts as a brake to keep the current from moving too fast), jumps through the forward-facing LED diode to create light, and drops into the common Ground rail to complete the loop.

For any LED that is not supposed to light up for that specific number, the microcontroller keeps its output pin to 0V. Because there is no voltage difference between a 0V pin and a 0V Ground rail, no current flows, and those specific LEDs remain dark.
