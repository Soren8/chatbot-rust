import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import org.junit.Before;
import org.junit.Test;

public final class JUnitShimRunner {
    private JUnitShimRunner() {
    }

    public static void main(String[] args) {
        int testsRun = 0;
        int failures = 0;
        for (String className : args) {
            try {
                Class<?> testClass = Class.forName(className);
                Method[] methods = testClass.getDeclaredMethods();
                Arrays.sort(methods, Comparator.comparing(Method::getName));
                List<Method> beforeMethods = new ArrayList<>();
                List<Method> testMethods = new ArrayList<>();
                for (Method method : methods) {
                    if (method.isAnnotationPresent(Before.class)) {
                        beforeMethods.add(method);
                    }
                    if (method.isAnnotationPresent(Test.class)) {
                        testMethods.add(method);
                    }
                }
                for (Method testMethod : testMethods) {
                    testsRun++;
                    Object instance = testClass.getDeclaredConstructor().newInstance();
                    Throwable failure = null;
                    try {
                        for (Method beforeMethod : beforeMethods) {
                            beforeMethod.setAccessible(true);
                            beforeMethod.invoke(instance);
                        }
                        testMethod.setAccessible(true);
                        testMethod.invoke(instance);
                    } catch (InvocationTargetException exception) {
                        failure = exception.getCause();
                    } catch (Throwable throwable) {
                        failure = throwable;
                    }
                    if (failure == null) {
                        System.out.println("PASS " + className + "." + testMethod.getName());
                    } else {
                        failures++;
                        System.out.println("FAIL " + className + "." + testMethod.getName() + ": " + failure);
                    }
                }
            } catch (Throwable throwable) {
                failures++;
                System.out.println("FAIL " + className + ": " + throwable);
            }
        }
        if (testsRun == 0 || failures > 0) {
            System.exit(1);
        }
    }
}
