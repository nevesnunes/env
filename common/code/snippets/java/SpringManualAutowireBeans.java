@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes = SOAPHandlerTestConfig.class)
public class SOAPHandlerTest {
    private static ApplicationContext applicationContext;

    @BeforeClass
    public static void setUp() throws Exception {
        applicationContext = new AnnotationConfigApplicationContext(SOAPHandlerTestConfig.class);
        AutowireCapableBeanFactory beanFactory = applicationContext.getAutowireCapableBeanFactory();
        beanFactory.autowireBean(endpointPort);
    }
}
