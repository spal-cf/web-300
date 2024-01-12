import java.util.Random;
import java.util.Scanner;

public class DebuggerTest {

    private static Random random = new Random();
    
    public static void main(String[] args) {
        int num = generateRandomNumber();
        Scanner scanner = new Scanner(System.in);
        System.out.println("Guess a number between 1 and 100.");
        try {
            int answer = scanner.nextInt();
            scanner.close();
            System.out.println("Your guess was: " + answer);
            if (answer == num) {
                System.out.println("You are correct!");
            } else {
                System.out.println("Incorrect. The answer was " + num);
            }
        } catch (Exception e) {
            System.out.println("That's not a number.");
        } finally {
            scanner.close();
        }
        System.exit(0);
    }

    public static int generateRandomNumber() {
        return random.nextInt(100) + 1;
    }
}