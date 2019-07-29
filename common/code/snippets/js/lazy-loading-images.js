class Image extends PureComponent {
    componentDidMount() {
        this.observer = new IntersectionObserver(
            entries => {
                entries.forEach(entry => {
                    const {
                        isIntersecting
                    } = entry;

                    if (isIntersecting) {
                        this.element.src = this.props.src;
                        this.observer = this.observer.disconnect();
                    }
                });
            }, {
                root: document.querySelector(".container")
            }
        );
        this.observer.observe(this.element);
    }

    render() {
        return <img ref={el => this.element = el} />;
    }
}
